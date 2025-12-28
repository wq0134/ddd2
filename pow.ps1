# Feather Account Decrypter
# For account2.txt files

[CmdletBinding()]
param(
    [string]$InputFile = "$env:APPDATA\.feather\account2.txt",
    [string]$OutputFile = "$env:APPDATA\.feather\account2_decrypted.json",
    [switch]$Verbose
)

# Add required .NET assemblies
Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Core

function Get-EncryptionKey {
    $localStatePath = "$env:APPDATA\Feather Launcher\Local State"
    
    if (-not (Test-Path $localStatePath)) {
        Write-Error "Local State file not found at: $localStatePath"
        return $null
    }
    
    try {
        $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json
        $encryptedKey = $localState.os_crypt.encrypted_key
        
        if (-not $encryptedKey) {
            Write-Error "No encryption key found in Local State"
            return $null
        }
        
        # Decode base64
        $encryptedBytes = [Convert]::FromBase64String($encryptedKey)
        
        # Remove "DPAPI" prefix (5 bytes) if present
        if ($encryptedBytes.Length -gt 5 -and 
            [System.Text.Encoding]::ASCII.GetString($encryptedBytes[0..4]) -eq 'DPAPI') {
            $encryptedBytes = $encryptedBytes[5..($encryptedBytes.Length - 1)]
        }
        
        # Decrypt using DPAPI
        $decryptedKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedBytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        
        return $decryptedKey
    }
    catch {
        Write-Error "Failed to extract encryption key: $_"
        return $null
    }
}

function Decrypt-FeatherData {
    param(
        [byte[]]$EncryptedData,
        [byte[]]$Key
    )
    
    try {
        # Check if data starts with version prefix (v10/v11)
        $prefix = [System.Text.Encoding]::ASCII.GetString($EncryptedData[0..2])
        
        if ($prefix -match '^v1[01]$') {
            # Standard Chrome/Electron format
            $nonce = $EncryptedData[3..14]  # 12 bytes nonce
            $ciphertextWithTag = $EncryptedData[15..($EncryptedData.Length - 1)]
            $tag = $ciphertextWithTag[($ciphertextWithTag.Length - 16)..($ciphertextWithTag.Length - 1)]
            $ciphertext = $ciphertextWithTag[0..($ciphertextWithTag.Length - 17)]
            
            if ($Verbose) {
                Write-Host "Detected format: $prefix" -ForegroundColor Cyan
                Write-Host "Nonce length: $($nonce.Length)" -ForegroundColor Gray
                Write-Host "Ciphertext length: $($ciphertext.Length)" -ForegroundColor Gray
                Write-Host "Tag length: $($tag.Length)" -ForegroundColor Gray
            }
            
            return Invoke-AesGcmDecryption -Key $Key -Nonce $nonce -Ciphertext $ciphertext -Tag $tag
        }
        else {
            # Try raw AES-GCM format
            if ($EncryptedData.Length >= 28) {  # Minimum for nonce + data + tag
                $nonce = $EncryptedData[0..11]
                $tag = $EncryptedData[($EncryptedData.Length - 16)..($EncryptedData.Length - 1)]
                $ciphertext = $EncryptedData[12..($EncryptedData.Length - 17)]
                
                if ($Verbose) {
                    Write-Host "Detected format: Raw AES-GCM" -ForegroundColor Cyan
                }
                
                return Invoke-AesGcmDecryption -Key $Key -Nonce $nonce -Ciphertext $ciphertext -Tag $tag
            }
            else {
                # Try AES-CBC
                if ($EncryptedData.Length >= 32) {
                    if ($Verbose) {
                        Write-Host "Trying AES-CBC decryption..." -ForegroundColor Yellow
                    }
                    
                    return Invoke-AesCbcDecryption -EncryptedData $EncryptedData -Key $Key
                }
                else {
                    throw "Data too short for any known encryption format"
                }
            }
        }
    }
    catch {
        throw "Decryption failed: $_"
    }
}

function Invoke-AesGcmDecryption {
    param(
        [byte[]]$Key,
        [byte[]]$Nonce,
        [byte[]]$Ciphertext,
        [byte[]]$Tag
    )
    
    # Try .NET 5+ AesGcm first
    $aesGcmType = [Type]::GetType('System.Security.Cryptography.AesGcm, System.Security.Cryptography.Algorithms')
    
    if ($aesGcmType -and $PSVersionTable.PSVersion -ge [Version]"7.0") {
        if ($Verbose) {
            Write-Host "Using .NET AesGcm class..." -ForegroundColor Gray
        }
        
        $plaintext = [byte[]]::new($Ciphertext.Length)
        $aes = [System.Security.Cryptography.AesGcm]::new($Key)
        $aes.Decrypt($Nonce, $Ciphertext, $Tag, $plaintext)
        return $plaintext
    }
    else {
        # Fallback to custom implementation
        if ($Verbose) {
            Write-Host "Using fallback decryption..." -ForegroundColor Gray
        }
        
        return Invoke-BouncyCastleDecryption -Key $Key -Nonce $Nonce -Ciphertext $Ciphertext -Tag $Tag
    }
}

function Invoke-AesCbcDecryption {
    param(
        [byte[]]$EncryptedData,
        [byte[]]$Key
    )
    
    try {
        # Try different IV positions
        $iv = $EncryptedData[0..15]
        $ciphertext = $EncryptedData[16..($EncryptedData.Length - 1)]
        
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $Key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $decryptor = $aes.CreateDecryptor()
        $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        
        return $plaintext
    }
    catch {
        # Try without assuming IV at start
        try {
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $Key
            $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            
            $decryptor = $aes.CreateDecryptor()
            $plaintext = $decryptor.TransformFinalBlock($EncryptedData, 0, $EncryptedData.Length)
            
            return $plaintext
        }
        catch {
            throw "AES-CBC decryption failed: $_"
        }
    }
}

function Invoke-BouncyCastleDecryption {
    param(
        [byte[]]$Key,
        [byte[]]$Nonce,
        [byte[]]$Ciphertext,
        [byte[]]$Tag
    )
    
    # This is a simplified fallback - in practice you might need BouncyCastle
    # For now, we'll use a Windows API approach
    
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    
    public class NativeCrypto {
        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDecrypt(
            IntPtr hKey,
            byte[] pbInput,
            int cbInput,
            IntPtr pPaddingInfo,
            byte[] pbIV,
            int cbIV,
            byte[] pbOutput,
            int cbOutput,
            out int pcbResult,
            uint dwFlags);
            
        public const uint BCRYPT_SUCCESS = 0x00000000;
    }
"@

    # Simplified approach - you might need to implement proper GCM via Windows CNG
    throw "Advanced decryption requires BouncyCastle library or .NET 5+"
}

function Save-DecryptedData {
    param(
        [byte[]]$Data,
        [string]$Path
    )
    
    try {
        # Try to decode as UTF-8 JSON
        $text = [System.Text.Encoding]::UTF8.GetString($Data)
        
        # Validate if it looks like JSON
        $text = $text.Trim()
        if ($text.StartsWith('{') -or $text.StartsWith('[')) {
            try {
                $json = $text | ConvertFrom-Json -ErrorAction Stop
                $formattedJson = $json | ConvertTo-Json -Depth 10
                [System.IO.File]::WriteAllText($Path, $formattedJson, [System.Text.Encoding]::UTF8)
                Write-Host "Saved as formatted JSON" -ForegroundColor Green
                return $text
            }
            catch {
                # Not valid JSON, save as raw text
                [System.IO.File]::WriteAllBytes($Path, $Data)
                Write-Host "Saved as raw data (not valid JSON)" -ForegroundColor Yellow
                return $text
            }
        }
        else {
            # Save as raw bytes
            [System.IO.File]::WriteAllBytes($Path, $Data)
            Write-Host "Saved as raw binary data" -ForegroundColor Yellow
            return $text
        }
    }
    catch {
        # Save as raw bytes
        [System.IO.File]::WriteAllBytes($Path, $Data)
        Write-Host "Saved as raw bytes" -ForegroundColor Gray
        return [System.Convert]::ToBase64String($Data)
    }
}

# Main execution
try {
    Write-Host "Feather Account Decrypter" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    
    # 1. Get encryption key
    Write-Host "`n[1/3] Extracting encryption key..." -ForegroundColor White
    $key = Get-EncryptionKey
    if (-not $key) {
        exit 1
    }
    Write-Host "✓ Key extracted ($($key.Length) bytes)" -ForegroundColor Green
    
    # 2. Read encrypted file
    Write-Host "`n[2/3] Reading encrypted file..." -ForegroundColor White
    if (-not (Test-Path $InputFile)) {
        Write-Error "Input file not found: $InputFile"
        exit 1
    }
    
    $encryptedData = [System.IO.File]::ReadAllBytes($InputFile)
    Write-Host "✓ Read $($encryptedData.Length) bytes from: $InputFile" -ForegroundColor Green
    
    # Show hex preview
    if ($Verbose) {
        $hexPreview = ($encryptedData[0..15] | ForEach-Object { $_.ToString("X2") }) -join ' '
        Write-Host "Hex preview (first 16 bytes): $hexPreview" -ForegroundColor DarkGray
    }
    
    # 3. Decrypt data
    Write-Host "`n[3/3] Decrypting data..." -ForegroundColor White
    $decryptedData = Decrypt-FeatherData -EncryptedData $encryptedData -Key $key
    
    if (-not $decryptedData) {
        Write-Error "Decryption produced no data"
        exit 1
    }
    
    Write-Host "✓ Decryption successful!" -ForegroundColor Green
    Write-Host "Decrypted size: $($decryptedData.Length) bytes" -ForegroundColor Gray
    
    # 4. Save results
    Write-Host "`nSaving results..." -ForegroundColor White
    $decryptedText = Save-DecryptedData -Data $decryptedData -Path $OutputFile
    Write-Host "✓ Output saved to: $OutputFile" -ForegroundColor Green
    
    # 5. Show preview
    Write-Host "`nPreview of decrypted content:" -ForegroundColor Cyan
    Write-Host "------------------------------" -ForegroundColor Cyan
    
    $previewLength = [Math]::Min($decryptedText.Length, 1000)
    $preview = $decryptedText.Substring(0, $previewLength)
    
    if ($preview.Contains("`n")) {
        $lines = $preview.Split("`n")
        for ($i = 0; $i -lt [Math]::Min(10, $lines.Length); $i++) {
            Write-Host $lines[$i] -ForegroundColor White
        }
        if ($lines.Length -gt 10) {
            Write-Host "... (truncated)" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host $preview -ForegroundColor White
        if ($decryptedText.Length -gt 1000) {
            Write-Host "`n... (truncated)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "`nDone!" -ForegroundColor Green
}
catch {
    Write-Error "Error: $_"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Make sure Feather launcher is installed and running" -ForegroundColor Gray
    Write-Host "2. Check if account2.txt exists in: $env:APPDATA\.feather\" -ForegroundColor Gray
    Write-Host "3. Try with the original account.txt file" -ForegroundColor Gray
    Write-Host "4. The file might be in a different format or corrupted" -ForegroundColor Gray
    exit 1
}
