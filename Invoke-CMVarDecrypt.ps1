<#
.SYNOPSIS
    Decrypts SCCM/ConfigMgr Variables.dat files.

.DESCRIPTION
    PowerShell port of CMvarDecrypt (https://github.com/1njected/CMvarDecrypt).

    Variables.dat files are produced by SCCM/ConfigMgr task sequence media (boot
    ISOs, PXE media) and can sometimes be found on administrative shares. They are
    encrypted with AES-128 using a key derived from a static GUID
    "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}" (or a custom password) and can contain
    secrets such as domain-join credentials.

    The key is derived exactly the way the Windows CryptoAPI does it:
      1. Hash the UTF-16LE key bytes with SHA1.
      2. XOR that 20-byte digest into a 64-byte buffer of 0x36.
      3. SHA1 the buffer; the first 16 bytes are the AES-128 key.
    Decryption is AES-128-CBC with an all-zero IV and PKCS7 padding.

.PARAMETER Path
    Path to the Variables.dat file. Accepts pipeline input (e.g. from Get-ChildItem).

.PARAMETER Password
    Optional custom password/key. If omitted, the default SCCM static key is used.

.PARAMETER OutFile
    Optional path to write the raw decrypted bytes to instead of returning text.

.PARAMETER Raw
    Return the decrypted content as a raw byte[] instead of a string.

.EXAMPLE
    .\Invoke-CMVarDecrypt.ps1 .\Variables.dat

.EXAMPLE
    .\Invoke-CMVarDecrypt.ps1 -Path .\Variables.dat -Password 'CustomKey'

.EXAMPLE
    Get-ChildItem -Recurse -Filter Variables.dat | .\Invoke-CMVarDecrypt.ps1

.EXAMPLE
    # Dot-source to reuse the function in your session:
    . .\Invoke-CMVarDecrypt.ps1
    Invoke-CMVarDecrypt .\Variables.dat -OutFile .\decrypted.xml
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName', 'LiteralPath')]
    [string]$Path,

    [Parameter(Position = 1)]
    [string]$Password,

    [string]$OutFile,

    [switch]$Raw
)

function Invoke-CMVarDecrypt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'LiteralPath')]
        [string]$Path,

        [Parameter(Position = 1)]
        [string]$Password,

        [string]$OutFile,

        [switch]$Raw
    )

    process {
        $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
        $bytes = [System.IO.File]::ReadAllBytes($resolved)

        # Header is 24 bytes:
        #   uint32  signature
        #   byte[8] unknown1
        #   uint32  encryptedsize   <-- offset 12
        #   byte[8] unknown2
        # Encrypted data starts at offset 24.
        if ($bytes.Length -lt 24) {
            throw "File '$resolved' is too small to contain a valid Variables.dat header (24 bytes)."
        }

        $encryptedSize = [System.BitConverter]::ToUInt32($bytes, 12)
        $dataOffset = 24

        if ([uint64]$dataOffset + [uint64]$encryptedSize -gt [uint64]$bytes.Length) {
            throw "Declared encrypted size ($encryptedSize) exceeds the available data in '$resolved'."
        }

        $cipher = New-Object byte[] $encryptedSize
        [System.Array]::Copy($bytes, $dataOffset, $cipher, 0, $encryptedSize)

        # Key string -> UTF-16LE bytes (CryptoAPI hashes the wide-char buffer).
        if ([string]::IsNullOrEmpty($Password)) {
            $keyString = '{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}'
        }
        else {
            Write-Verbose 'Using custom password/key.'
            $keyString = $Password
        }
        $keyBytes = [System.Text.Encoding]::Unicode.GetBytes($keyString)

        # Replicate CryptDeriveKey(CALG_AES_128, SHA1 hash):
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            $hash = $sha1.ComputeHash($keyBytes)            # 20 bytes
            $buf = New-Object byte[] 64
            for ($i = 0; $i -lt 64; $i++) { $buf[$i] = 0x36 }
            for ($i = 0; $i -lt $hash.Length; $i++) { $buf[$i] = $buf[$i] -bxor $hash[$i] }
            $derived = $sha1.ComputeHash($buf)              # 20 bytes
        }
        finally {
            $sha1.Dispose()
        }

        $aesKey = New-Object byte[] 16
        [System.Array]::Copy($derived, 0, $aesKey, 0, 16)   # AES-128 = first 16 bytes

        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.KeySize = 128
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $aesKey
            $aes.IV = New-Object byte[] 16                  # all-zero IV
            $decryptor = $aes.CreateDecryptor()
            try {
                $plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
            }
            catch [System.Security.Cryptography.CryptographicException] {
                throw "Decryption failed - wrong password/key or corrupt file. ($($_.Exception.Message))"
            }
            finally {
                $decryptor.Dispose()
            }
        }
        finally {
            $aes.Dispose()
        }

        if ($OutFile) {
            [System.IO.File]::WriteAllBytes((Join-Path -Path (Get-Location) -ChildPath $OutFile | ForEach-Object {
                        if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { $_ } }), $plain)
            Write-Verbose "Wrote $($plain.Length) decrypted bytes to '$OutFile'."
        }
        elseif ($Raw) {
            , $plain
        }
        else {
            # Variables.dat content is text (typically XML). Trim a trailing NUL if present.
            $text = [System.Text.Encoding]::UTF8.GetString($plain)
            $text.TrimEnd([char]0)
        }
    }
}

# Run directly when the script is executed (not dot-sourced) with a path argument.
if ($MyInvocation.InvocationName -ne '.' -and $PSBoundParameters.ContainsKey('Path')) {
    Invoke-CMVarDecrypt @PSBoundParameters
}
