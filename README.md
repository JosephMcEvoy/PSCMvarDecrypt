# PSCMvarDecrypt

A pure-PowerShell tool to decrypt SCCM/ConfigMgr `Variables.dat` files with the
default key `{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}` or a custom password.

`Variables.dat` files are produced by SCCM/ConfigMgr task sequence media (boot
ISOs and PXE media) and can sometimes be discovered on administrative shares.
They can contain credentials such as domain-join accounts.

This is a PowerShell port of [CMvarDecrypt](https://github.com/1njected/CMvarDecrypt).
It uses .NET crypto directly (no Windows CryptoAPI), so it needs no compilation
and runs on Windows PowerShell 5.1 and PowerShell 7+ (Windows/Linux/macOS).

## Usage

```powershell
# Just pass it the .dat (uses the default SCCM key)
.\Invoke-CMVarDecrypt.ps1 .\Variables.dat

# Custom password/key
.\Invoke-CMVarDecrypt.ps1 .\Variables.dat -Password 'CustomKey'

# Write the raw decrypted bytes to a file instead of printing text
.\Invoke-CMVarDecrypt.ps1 .\Variables.dat -OutFile .\decrypted.xml

# Find and decrypt every Variables.dat under a path (pipeline)
Get-ChildItem -Recurse -Filter Variables.dat | .\Invoke-CMVarDecrypt.ps1

# Or dot-source it and reuse the function
. .\Invoke-CMVarDecrypt.ps1
Invoke-CMVarDecrypt -Path .\Variables.dat -Raw   # returns a byte[]
```

## How it works

- **Header** (24 bytes): the encrypted size is a little-endian `uint32` at offset
  12, and the ciphertext begins at offset 24.
- **Key derivation**: replicates the Windows CryptoAPI
  `CryptDeriveKey(CALG_AES_128, SHA1)` algorithm — SHA1 of the UTF-16LE key,
  XORed into a 64-byte `0x36` buffer, SHA1'd again, with the first 16 bytes used
  as the AES-128 key.
- **Decryption**: AES-128-CBC with an all-zero IV and PKCS7 padding.

## See also

PXEThief from MWR CyberSec can perform decryption and a lot more:
https://github.com/MWR-CyberSec/PXEThief
