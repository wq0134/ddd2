#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$AccountPath = "$env:APPDATA\.feather\account2.txt",  # Changed to account2.txt
    [string]$LocalStatePath = "$env:APPDATA\Feather Launcher\Local State",
    [string]$OutputPath = "$env:APPDATA\.feather\account2_decrypted.txt"  # Changed output filename
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
    $dpapiBlobStart = 5
    $dpapiBlob = $encryptedKey[$dpapiBlobStart..($encryptedKey.Length - 1)]

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

    $versionPrefix = [Text.Encoding]::ASCII.GetString($EncryptedData[0..2])

    if ($versionPrefix -notmatch '^v1[01]$') {
        throw "Unknown encryption version: $versionPrefix"
    }

    $nonce = $EncryptedData[3..14]
    $ciphertextWithTag = $EncryptedData[15..($EncryptedData.Length - 1)]

    $tagLength = 16
    $ciphertext = $ciphertextWithTag[0..($ciphertextWithTag.Length - $tagLength - 1)]
    $tag = $ciphertextWithTag[($ciphertextWithTag.Length - $tagLength)..($ciphertextWithTag.Length - 1)]

    $aesGcmType = [Type]::GetType('System.Security.Cryptography.AesGcm, System.Security.Cryptography.Algorithms')

    if ($aesGcmType) {
        $plaintext = [byte[]]::new($ciphertext.Length)
        $aesGcm = [Activator]::CreateInstance($aesGcmType, @(,$Key))
        $aesGcmType.GetMethod('Decrypt', @([byte[]], [byte[]], [byte[]], [byte[]], [byte[]])).Invoke(
            $aesGcm, @($nonce, $ciphertext, $tag, $plaintext, $null))
        $aesGcm.Dispose()
        return $plaintext
    }
    else {
        return Decrypt-AesGcmBCrypt -Key $Key -Nonce $nonce -Ciphertext $ciphertext -Tag $tag
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

    public const uint STATUS_SUCCESS = 0;
    public const string BCRYPT_AES_ALGORITHM = "AES";
    public const string BCRYPT_CHAINING_MODE = "ChainingMode";
    public const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
}
'@

    Add-Type -TypeDefinition $bcryptSignature -ErrorAction SilentlyContinue

    $hAlgorithm = [IntPtr]::Zero
    $hKey = [IntPtr]::Zero

    try {
        $status = [BCryptAesGcm]::BCryptOpenAlgorithmProvider(
            [ref]$hAlgorithm,
            [BCryptAesGcm]::BCRYPT_AES_ALGORITHM,
            $null,
            0)

        if ($status -ne 0) { throw "BCryptOpenAlgorithmProvider failed: 0x$($status.ToString('X8'))" }

        $gcmMode = [Text.Encoding]::Unicode.GetBytes([BCryptAesGcm]::BCRYPT_CHAIN_MODE_GCM + "`0")
        $status = [BCryptAesGcm]::BCryptSetProperty(
            $hAlgorithm,
            [BCryptAesGcm]::BCRYPT_CHAINING_MODE,
            $gcmMode,
            $gcmMode.Length,
            0)

        if ($status -ne 0) { throw "BCryptSetProperty failed: 0x$($status.ToString('X8'))" }

        $status = [BCryptAesGcm]::BCryptGenerateSymmetricKey(
            $hAlgorithm,
            [ref]$hKey,
            [IntPtr]::Zero,
            0,
            $Key,
            $Key.Length,
            0)

        if ($status -ne 0) { throw "BCryptGenerateSymmetricKey failed: 0x$($status.ToString('X8'))" }

        $authInfo = New-Object BCryptAesGcm+BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        $authInfo.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($authInfo)
        $authInfo.dwInfoVersion = 1

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
            $null,
            0,
            $plaintext,
            $plaintext.Length,
            [ref]$resultSize,
            0)

        $nonceHandle.Free()
        $tagHandle.Free()
        [Runtime.InteropServices.Marshal]::FreeHGlobal($authInfoPtr)

        if ($status -ne 0) { throw "BCryptDecrypt failed: 0x$($status.ToString('X8'))" }

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

try {
    Write-Host "Extracting AES key from Local State..." -ForegroundColor Cyan
    $aesKey = Get-DecryptionKey -LocalStatePath $LocalStatePath
    Write-Host "Key extracted successfully ($($aesKey.Length) bytes)" -ForegroundColor Green

    if (-not (Test-Path $AccountPath)) {
        throw "Account file not found: $AccountPath"
    }

    Write-Host "Reading encrypted account data from account2.txt..." -ForegroundColor Cyan  # Updated message
    $encryptedData = [IO.File]::ReadAllBytes($AccountPath)
    Write-Host "Read $($encryptedData.Length) bytes" -ForegroundColor Green

    Write-Host "Decrypting with AES-GCM..." -ForegroundColor Cyan
    $plaintext = Decrypt-AesGcm -EncryptedData $encryptedData -Key $aesKey

    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    [IO.File]::WriteAllBytes($OutputPath, $plaintext)
    Write-Host "Decrypted data written to: $OutputPath" -ForegroundColor Green

    $decryptedText = [Text.Encoding]::UTF8.GetString($plaintext)
    Write-Host "`nDecrypted content:" -ForegroundColor Yellow
    Write-Host $decryptedText
}
catch {
    Write-Error "Decryption failed: $_"
    exit 1
}