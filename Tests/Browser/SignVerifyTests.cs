using FluentCrossPlatformCrypto.Tests.Browser.TestFramework;
using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Browser;

public class SignVerifyTests : Helpers.SignVerifyTests
{
  public void Add(Suite suite)
  {
    Assert = new Assert();

    TestSymSignVerify("HMAC 256", Algorithm.Hmac[Algorithm.Digest.Sha256].Import, HmacConstants.Key256, 32);
    TestSymSignVerify("HMAC 512", Algorithm.Hmac[Algorithm.Digest.Sha512].Import, HmacConstants.Key512, 64);

    void TestSymSignVerify<T>(string description, IKeyManagerImportRaw<T> importAlgo,
      string keyData, int expectedSignature)
      where T : ISign, IVerify =>
      suite.Test($"Sign Verify {description}", () => base.SymSignVerify(importAlgo, keyData, expectedSignature));

    TestSymConstVerify("HMAC 256", Algorithm.Hmac[Algorithm.Digest.Sha256].Import, HmacConstants.Key256,
      HmacConstants.Signature256);
    TestSymConstVerify("HMAC 512", Algorithm.Hmac[Algorithm.Digest.Sha512].Import, HmacConstants.Key512,
      HmacConstants.Signature512);

    void TestSymConstVerify<T>(string description, IKeyManagerImportRaw<T> importAlgo,
      string keyData, string expectedSignature)
      where T : ISign, IVerify =>
      suite.Test($"Const Verify {description}", () => base.SymConstVerify(importAlgo, keyData, expectedSignature));


    TestAsymSignVerify("RSASSA-PKCS1-v1_5 256", Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1, 256);
    TestAsymSignVerify("RSA-PSS 256", Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.PublicKey2, 256);
    TestAsymSignVerify("RSA-PSS 512", Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1, 256);
    TestAsymSignVerify( "ECDSA P256 SHA256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP256B, EcConstants.PublicKeyP256B, 64 );
    TestAsymSignVerify( "ECDSA P256 SHA384", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP256B, EcConstants.PublicKeyP256B, 64 );
    TestAsymSignVerify( "ECDSA P256 SHA512", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP256B, EcConstants.PublicKeyP256B, 64 );
    TestAsymSignVerify( "ECDSA P384 SHA256", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP384B, EcConstants.PublicKeyP384B, 96 );
    TestAsymSignVerify( "ECDSA P384 SHA384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP384B, EcConstants.PublicKeyP384B, 96 );
    TestAsymSignVerify( "ECDSA P384 SHA512", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP384B, EcConstants.PublicKeyP384B, 96 );
    TestAsymSignVerify( "ECDSA P521 SHA256", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP521B, EcConstants.PublicKeyP521B, 132);
    TestAsymSignVerify( "ECDSA P521 SHA384", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP521B, EcConstants.PublicKeyP521B, 132);
    TestAsymSignVerify( "ECDSA P521 SHA512", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP521B, EcConstants.PublicKeyP521B, 132);


    void TestAsymSignVerify<TPublic, TPrivate>(string description, IKeyManagerImport<TPublic, TPrivate> importAlgo,
      string privateKeyData, string publicKeyData, int expectedSignature)
      where TPrivate : ISign where TPublic : IVerify =>
      suite.Test($"Sign Verify {description}",
        () => base.AsymSignVerify(importAlgo, privateKeyData, publicKeyData, expectedSignature));


    TestAsymConstVerify("RSASSA-PKCS1-v1_5 256", Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Import,
      RsaConstants.PublicKey1, RsaConstants.SignatureKey1_Pkcs256);
    TestAsymConstVerify("RSA-PSS 256", Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import, RsaConstants.PublicKey2,
      RsaConstants.SignatureKey2_Native_Pss256);
    TestAsymConstVerify("RSA-PSS 512", Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Import, RsaConstants.PublicKey1,
      RsaConstants.SignatureKey1_Native_Pss512);
    TestAsymConstVerify("RSA-PSS 256", Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import, RsaConstants.PublicKey2,
      RsaConstants.SignatureKey2_Browser_Pss256);
    TestAsymConstVerify("RSA-PSS 512", Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Import, RsaConstants.PublicKey1,
      RsaConstants.SignatureKey1_Browser_Pss512);
    TestAsymConstVerify("ECDSA P256 SHA256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N256);
    TestAsymConstVerify("ECDSA P256 SHA384", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N384);
    TestAsymConstVerify("ECDSA P256 SHA512", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N512);
    TestAsymConstVerify("ECDSA P384 SHA256", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N256);
    TestAsymConstVerify("ECDSA P384 SHA384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N384);
    TestAsymConstVerify("ECDSA P384 SHA512", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N512);
    TestAsymConstVerify("ECDSA P521 SHA256", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N256);
    TestAsymConstVerify("ECDSA P521 SHA384", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N384);
    TestAsymConstVerify("ECDSA P521 SHA512", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N512);
    TestAsymConstVerify("ECDSA P256 SHA256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B256);
    TestAsymConstVerify("ECDSA P256 SHA384", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B384);
    TestAsymConstVerify("ECDSA P256 SHA512", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B512);
    TestAsymConstVerify("ECDSA P384 SHA256", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B256);
    TestAsymConstVerify("ECDSA P384 SHA384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B384);
    TestAsymConstVerify("ECDSA P384 SHA512", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B512);
    TestAsymConstVerify("ECDSA P521 SHA256", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B256);
    TestAsymConstVerify("ECDSA P521 SHA384", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B384);
    TestAsymConstVerify("ECDSA P521 SHA512", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B512);

    void TestAsymConstVerify<TPublic, TPrivate>(string description, IKeyManagerImport<TPublic, TPrivate> importAlgo,
      string publicKeyData, string signature)
      where TPrivate : ISign where TPublic : IVerify =>
      suite.Test($"Const Verify {description}", () => base.AsymConstVerify(importAlgo, publicKeyData, signature));
  }
}