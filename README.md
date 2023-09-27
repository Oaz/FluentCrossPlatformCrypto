## Overview

FluentCrossPlatformCrypto is a wrapper offering
- a fluent interface on top of some .NET native cryptography functions
- the same interface in a browser-wasm environment using interop to the JavaScript Web Crypto API

### Warning

Please keep in mind that this library is a wrapper around cryptography APIs and the keys might be visible to any code having access to the computer memory.

## Available Algorithms

Feature           | .NET System.Security.Cryptography           | Web Crypto API
------------------|---------------------------------------------|---------------
Digest            | SHA1 / SHA256 / SHA384 / SHA512             | subtle.digest
Encrypt / Decrypt | Aes / RSA                                   | subtle.encrypt / decrypt
Sign / Verify     | RSA / ECDsa / HMAC                          | subtle.sign / verify
Key Derivation    | ECDiffieHellman / Rfc2898DeriveBytes / HKDF | subtle.deriveBits

## Examples

### RSA signature verification

```csharp
var rsaPublicKey = await Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import
  .Spki("the signer public key in base64".FromBase64());
var isValid = await rsaPublicKey.Verify(
    Encoding.UTF8.GetBytes("the signed message"),
    "the signature in base64".FromBase64()
  );
```

### AES encryption after PBKDF2 password derivation

```csharp
var pbkdf2 = await Algorithm.Pbkdf2[Algorithm.Digest.Sha256].Import.Text("My password");
var aes = await pbkdf2.With(iterations:1000).DeriveToAes();
var encrypted = await aes.Encrypt("My secret information");
```

### EC DiffieHellman exchange followed by HKDF derivation

```csharp
var import = Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha384].Import;
var alicePrivateKey = await import.Pkcs8("Alice private key".FromBase64());
var bobPublicKey = await import.Spki("Bob public key".FromBase64());
var sharedSecret = await alicePrivateKey.With(bobPublicKey).Derive();
var hkdf = await Algorithm.Hkdf[Algorithm.Digest.Sha256].Import.Raw(sharedSecret);
var dedicatedKey = await hkdf.With(info: "for some intent").DeriveToAes();
```



