# CMvarDecrypt

This tool can decrypt SCCM/ConfigMgr Variables.dat files with the default key "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}" or custom password.

Variables.dat files can sometimes be discoved on administrative shares and boot ISO's created with SCCM/ConfigMgr and can contain credentials such as domain join accounts.


Usage (original C++ build):
````
CMvarDecrypt.exe <Path to Variables.dat file>
CMvarDecrypt.exe <Path to Variables.dat file> <custom password>
````

## PowerShell version

`Invoke-CMVarDecrypt.ps1` is a pure-PowerShell port that needs no compilation and
runs on Windows PowerShell 5.1 and PowerShell 7+ (Windows/Linux/macOS). It uses
.NET crypto directly, so it does not depend on the Windows CryptoAPI.

````powershell
# Run as a script, just pass it the .dat
.\Invoke-CMVarDecrypt.ps1 .\Variables.dat

# Custom password/key
.\Invoke-CMVarDecrypt.ps1 .\Variables.dat -Password 'CustomKey'

# Write the raw decrypted bytes to a file
.\Invoke-CMVarDecrypt.ps1 .\Variables.dat -OutFile .\decrypted.xml

# Find and decrypt every Variables.dat under a path (pipeline)
Get-ChildItem -Recurse -Filter Variables.dat | .\Invoke-CMVarDecrypt.ps1

# Or dot-source it and reuse the function
. .\Invoke-CMVarDecrypt.ps1
Invoke-CMVarDecrypt -Path .\Variables.dat -Raw   # returns a byte[]
````

How it works: the 24-byte header carries the encrypted size (uint32 at offset 12)
and the ciphertext begins at offset 24. The AES-128 key is derived the same way the
Windows CryptoAPI's `CryptDeriveKey` does it - SHA1 of the UTF-16LE key, XORed into a
64-byte `0x36` buffer, SHA1'd again, first 16 bytes taken as the key - then the data
is decrypted with AES-128-CBC using an all-zero IV and PKCS7 padding.

PXEThief from MWR CyberSec can perform decryption and alot more:
https://github.com/MWR-CyberSec/PXEThief
