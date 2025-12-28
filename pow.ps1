#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$AccountPath = "$env:APPDATA\.feather\account2.txt",
    [string]$LocalStatePath = "$env:APPDATA\Feather Launcher\Local State",
    [string]$OutputPath = "$env:APPDATA\.feather\account2_decrypted.txt"
)

Add-Type -AssemblyName System.Security

function Get-DecryptionKey {
    param([string]$LocalStatePath)

    if (-not (Test-Path $LocalStatePath)) {
        throw "Local State not found: $LocalStatePath"
    }

    $localState = Get-Content $LocalStatePath -Raw | ConvertFrom-Json
    $encryptedKeyB64 = $localState.os_crypt.encrypted_key

    if (-not $encryptedKeyB64) {
        throw "No encrypted_key found in Local State"
    }

    $encryptedKey = [Convert]::FromBase64String($encryptedKeyB64)
    
    # Check if it's DPAPI encrypted (starts with DPAPI)
    if ($encryptedKey.Length -ge 5 -and [Text.Encoding]::ASCII.GetString($encryptedKey[0..4]) -eq 'DPAPI') {
        $dpapiBlob = $encryptedKey[5..($encryptedKey.Length - 1)]
    } else {
        $dpapiBlob = $encryptedKey
    }

    $aesKey = [Security.Cryptography.ProtectedData]::Unprotect(
        $dpapiBlob,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    return $aesKey
}

function Decrypt-AesGcm {
    param(
        [byte[]]$EncryptedData,
        [byte[]]$Key
    )

    try {
        # Check if data starts with v10 or v11 (common for Chrome/Electron based apps)
        if ($EncryptedData.Length -lt 3) {
            throw "Encrypted data too short"
        }
        
        $versionPrefix = [Text.Encoding]::ASCII.GetString($EncryptedData[0..2])
        
        if ($versionPrefix -match '^v1[01]$') {
            # Standard v10/v11 format
            $nonce = $EncryptedData[3..14]
            $ciphertextWithTag = $EncryptedData[15..($EncryptedData.Length - 1)]
            
            $tagLength = 16
            if ($ciphertextWithTag.Length -lt $tagLength) {
                throw "Ciphertext too short for GCM tag"
            }
            
            $ciphertext = $ciphertextWithTag[0..($ciphertextWithTag.Length - $tagLength - 1)]
            $tag = $ciphertextWithTag[($ciphertextWithTag.Length - $tagLength)..($ciphertextWithTag.Length - 1)]
        } else {
            # Try different format - might be raw AES-GCM without version prefix
            # Assuming first 12 bytes are nonce, last 16 bytes are tag
            if ($EncryptedData.Length -lt 28) {  # Need at least 12 nonce + 1 data + 16 tag
                throw "Data too short for AES-GCM"
            }
            
            $nonce = $EncryptedData[0..11]
            $tag = $EncryptedData[($EncryptedData.Length - 16)..($EncryptedData.Length - 1)]
            $ciphertext = $EncryptedData[12..($EncryptedData.Length - 17)]
        }

        # Try using System.Security.Cryptography.AesGcm if available (.NET Core 3.0+)
        $aesGcmType = [Type]::GetType('System.Security.Cryptography.AesGcm, System.Security.Cryptography.Algorithms')
        
        if ($aesGcmType -and $PSVersionTable.PSVersion -ge [Version]"7.0") {
            Write-Host "Using .NET Core AES-GCM implementation..." -ForegroundColor Cyan
            $plaintext = [byte[]]::new($ciphertext.Length)
            $aesGcm = [Activator]::CreateInstance($aesGcmType, @(,$Key))
            $aesGcm.Decrypt($nonce, $ciphertext, $tag, $plaintext)
            return $plaintext
        }
        else {
            # Fall back to BCrypt
            Write-Host "Using BCrypt for AES-GCM..." -ForegroundColor Cyan
            return Decrypt-AesGcmBCrypt -Key $Key -Nonce $nonce -Ciphertext $ciphertext -Tag $tag
        }
    }
    catch {
        throw "AES-GCM decryption failed: $_"
    }
}

function Decrypt-AesGcmBCrypt {
    param(
        [byte[]]$Key,
        [byte[]]$Nonce,
        [byte[]]$Ciphertext,
        [byte[]]$Tag
    )

    $bcryptSignature = @'
using System;
using System.Runtime.InteropServices;

public class BCryptAesGcm {
    [DllImport("bcrypt.dll")]
    public static extern uint BCryptOpenAlgorithmProvider(
        out IntPtr hAlgorithm,
        [MarshalAs(UnmanagedType.LPWStr)] string algId,
        [MarshalAs(UnmanagedType.LPWStr)] string implementation,
        uint flags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptSetProperty(
        IntPtr hObject,
        [MarshalAs(UnmanagedType.LPWStr)] string property,
        byte[] input,
        int inputSize,
        uint flags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptGenerateSymmetricKey(
        IntPtr hAlgorithm,
        out IntPtr hKey,
        IntPtr keyObject,
        int keyObjectSize,
        byte[] secret,
        int secretSize,
        uint flags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptDecrypt(
        IntPtr hKey,
        byte[] input,
        int inputSize,
        IntPtr paddingInfo,
        byte[] iv,
        int ivSize,
        byte[] output,
        int outputSize,
        out int resultSize,
        uint flags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint flags);

    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;
    }

    public const uint BCRYPT_SUCCESS = 0x00000000;
    public const uint STATUS_AUTH_TAG_MISMATCH = 0xC000A002;
    public const string BCRYPT_AES_ALGORITHM = "AES";
    public const string BCRYPT_CHAINING_MODE = "ChainingMode";
    public const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
    public const uint BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 0x00000001;
    public const uint BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG = 0x00000002;
}
'@

    try {
        Add-Type -TypeDefinition $bcryptSignature -ErrorAction Stop
    }
    catch {
        throw "Failed to load BCrypt functions: $_"
    }

    $hAlgorithm = [IntPtr]::Zero
    $hKey = [IntPtr]::Zero

    try {
        $status = [BCryptAesGcm]::BCryptOpenAlgorithmProvider(
            [ref]$hAlgorithm,
            [BCryptAesGcm]::BCRYPT_AES_ALGORITHM,
            $null,
            0)

        if ($status -ne 0) { 
            throw "BCryptOpenAlgorithmProvider failed: 0x$($status.ToString('X8'))" 
        }

        $gcmMode = [Text.Encoding]::Unicode.GetBytes([BCryptAesGcm]::BCRYPT_CHAIN_MODE_GCM + "`0")
        $status = [BCryptAesGcm]::BCryptSetProperty(
            $hAlgorithm,
            [BCryptAesGcm]::BCRYPT_CHAINING_MODE,
            $gcmMode,
            $gcmMode.Length,
            0)

        if ($status -ne 0) { 
            throw "BCryptSetProperty failed: 0x$($status.ToString('X8'))" 
        }

        $status = [BCryptAesGcm]::BCryptGenerateSymmetricKey(
            $hAlgorithm,
            [ref]$hKey,
            [IntPtr]::Zero,
            0,
            $Key,
            $Key.Length,
            0)

        if ($status -ne 0) { 
            throw "BCryptGenerateSymmetricKey failed: 0x$($status.ToString('X8'))" 
        }

        $authInfo = New-Object BCryptAesGcm+BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        $authInfo.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([BCryptAesGcm+BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO])
        $authInfo.dwInfoVersion = 1
        $authInfo.dwFlags = [BCryptAesGcm]::BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG

        $nonceHandle = [Runtime.InteropServices.GCHandle]::Alloc($Nonce, [Runtime.InteropServices.GCHandleType]::Pinned)
        $tagHandle = [Runtime.InteropServices.GCHandle]::Alloc($Tag, [Runtime.InteropServices.GCHandleType]::Pinned)

        $authInfo.pbNonce = $nonceHandle.AddrOfPinnedObject()
        $authInfo.cbNonce = $Nonce.Length
        $authInfo.pbTag = $tagHandle.AddrOfPinnedObject()
        $authInfo.cbTag = $Tag.Length

        $authInfoSize = [Runtime.InteropServices.Marshal]::SizeOf($authInfo)
        $authInfoPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($authInfoSize)
        [Runtime.InteropServices.Marshal]::StructureToPtr($authInfo, $authInfoPtr, $false)

        $plaintext = [byte[]]::new($Ciphertext.Length)
        $resultSize = 0

        $status = [BCryptAesGcm]::BCryptDecrypt(
            $hKey,
            $Ciphertext,
            $Ciphertext.Length,
            $authInfoPtr,
            $null,  # IV is part of authInfo
            0,
            $plaintext,
            $plaintext.Length,
            [ref]$resultSize,
            0)

        $nonceHandle.Free()
        $tagHandle.Free()
        [Runtime.InteropServices.Marshal]::FreeHGlobal($authInfoPtr)

        if ($status -eq [BCryptAesGcm]::STATUS_AUTH_TAG_MISMATCH) {
            throw "Authentication tag mismatch - data may be corrupted or key is incorrect"
        }
        elseif ($status -ne 0) { 
            throw "BCryptDecrypt failed with error: 0x$($status.ToString('X8'))" 
        }

        return $plaintext[0..($resultSize - 1)]
    }
    finally {
        if ($hKey -ne [IntPtr]::Zero) {
            [void][BCryptAesGcm]::BCryptDestroyKey($hKey)
        }
        if ($hAlgorithm -ne [IntPtr]::Zero) {
            [void][BCryptAesGcm]::BCryptCloseAlgorithmProvider($hAlgorithm, 0)
        }
    }
}

# Alternative: Try AES-CBC decryption (some launchers use this)
function Decrypt-AesCbc {
    param(
        [byte[]]$EncryptedData,
        [byte[]]$Key
    )
    
    try {
        # Try to find initialization vector - might be at start of data
        $iv = $EncryptedData[0..15]
        $ciphertext = $EncryptedData[16..($EncryptedData.Length - 1)]
        
        $aes = [Security.Cryptography.Aes]::Create()
        $aes.Key = $Key
        $aes.IV = $iv
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        
        $decryptor = $aes.CreateDecryptor()
        $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        
        return $plaintext
    }
    catch {
        throw "AES-CBC decryption failed: $_"
    }
}

try {
    Write-Host "Extracting AES key from Local State..." -ForegroundColor Cyan
    $aesKey = Get-DecryptionKey -LocalStatePath $LocalStatePath
    Write-Host "Key extracted successfully ($($aesKey.Length) bytes)" -ForegroundColor Green

    if (-not (Test-Path $AccountPath)) {
        throw "Account file not found: $AccountPath"
    }

    Write-Host "Reading encrypted account data from account2.txt..." -ForegroundColor Cyan
    $encryptedData = [IO.File]::ReadAllBytes($AccountPath)
    Write-Host "Read $($encryptedData.Length) bytes" -ForegroundColor Green
    
    Write-Host "Data hex preview:" -ForegroundColor DarkGray
    $hexPreview = ($encryptedData[0..31] | ForEach-Object { $_.ToString("X2") }) -join ' '
    Write-Host "$hexPreview..." -ForegroundColor DarkGray

    Write-Host "`nAttempting decryption..." -ForegroundColor Yellow
    
    # Try multiple decryption methods
    $decryptionMethods = @("AES-GCM", "AES-CBC")
    $success = $false
    
    foreach ($method in $decryptionMethods) {
        try {
            Write-Host "Trying $method decryption..." -ForegroundColor Cyan
            
            if ($method -eq "AES-GCM") {
                $plaintext = Decrypt-AesGcm -EncryptedData $encryptedData -Key $aesKey
            } elseif ($method -eq "AES-CBC") {
                $plaintext = Decrypt-AesCbc -EncryptedData $encryptedData -Key $aesKey
            }
            
            $decryptedText = [Text.Encoding]::UTF8.GetString($plaintext)
            
            # Check if decrypted text looks valid (JSON or readable text)
            if ($decryptedText -match '^[\s\S]{10,}' -and ($decryptedText -match '{' -or $decryptedText -match '"' -or $decryptedText -match 'username' -or $decryptedText -match 'email')) {
                Write-Host "Success! Used $method decryption" -ForegroundColor Green
                $success = $true
                break
            } else {
                Write-Host "$method produced invalid output, trying next method..." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "$method failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    if (-not $success) {
        throw "All decryption methods failed. The file may be in a different format or corrupted."
    }

    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    [IO.File]::WriteAllBytes($OutputPath, $plaintext)
    Write-Host "Decrypted data written to: $OutputPath" -ForegroundColor Green

    Write-Host "`nDecrypted content:" -ForegroundColor Yellow
    Write-Host $decryptedText.Substring(0, [Math]::Min($decryptedText.Length, 500)) -ForegroundColor White
    if ($decryptedText.Length -gt 500) {
        Write-Host "... (truncated)" -ForegroundColor DarkGray
    }
}
catch {
    Write-Error "Decryption failed: $_"
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Make sure account2.txt is from the Feather launcher" -ForegroundColor Gray
    Write-Host "2. Check if the Local State file is from the same Feather installation" -ForegroundColor Gray
    Write-Host "3. The file might be in a different encryption format" -ForegroundColor Gray
    Write-Host "4. Try with the original account.txt file instead" -ForegroundColor Gray
    exit 1
}
