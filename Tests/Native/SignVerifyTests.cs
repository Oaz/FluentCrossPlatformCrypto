using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Native;

public class SignVerifyTests : Helpers.SignVerifyTests
{
  [SetUp]
  public void Init()
  {
    Assert = new Asserts();
  }
  
  [TestCaseSource(nameof(SymCases))]
  public Task SymSignVerify<T>(string description, IKeyManagerImportRaw<T> importAlgo,
    string keyData, int expectedSignature)
    where T : ISign, IVerify =>
    base.SymSignVerify(importAlgo, keyData, expectedSignature);
  
  public static object[] SymCases =
  {
    new object[] { "HMAC 256", Algorithm.Hmac[Algorithm.Digest.Sha256].Import, HmacConstants.Key256, 32 },
    new object[] { "HMAC 512", Algorithm.Hmac[Algorithm.Digest.Sha512].Import, HmacConstants.Key512, 64 },
  };
  
  [TestCaseSource(nameof(SymConstCases))]
  public Task SymConstVerify<T>(string description, IKeyManagerImportRaw<T> importAlgo,
    string keyData, string expectedSignature)
    where T : ISign, IVerify =>
    base.SymConstVerify(importAlgo, keyData, expectedSignature);
  
  public static object[] SymConstCases =
  {
    new object[] { "HMAC 256", Algorithm.Hmac[Algorithm.Digest.Sha256].Import, HmacConstants.Key256, HmacConstants.Signature256 },
    new object[] { "HMAC 512", Algorithm.Hmac[Algorithm.Digest.Sha512].Import, HmacConstants.Key512, HmacConstants.Signature512 },
  };
  
  [TestCaseSource(nameof(AsymCases))]
  public Task AsymSignVerify<TPublic,TPrivate>(string description, IKeyManagerImport<TPublic,TPrivate> importAlgo,
    string privateKeyData, string publicKeyData, int expectedSignature)
    where TPrivate : ISign where TPublic : IVerify =>
    base.AsymSignVerify(importAlgo, privateKeyData, publicKeyData, expectedSignature);
  
  public static object[] AsymCases =
  {
    new object[] { "RSASSA-PKCS1-v1_5 256", Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1, 256 },
    new object[] { "RSA-PSS 256", Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.PublicKey2, 256 },
    new object[] { "RSA-PSS 512", Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1, 256 },
    new object[] { "ECDSA P256 SHA256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP256N, EcConstants.PublicKeyP256N, 64 },
    new object[] { "ECDSA P256 SHA384", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP256N, EcConstants.PublicKeyP256N, 64 },
    new object[] { "ECDSA P256 SHA512", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP256N, EcConstants.PublicKeyP256N, 64 },
    new object[] { "ECDSA P384 SHA256", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP384N, EcConstants.PublicKeyP384N, 96 },
    new object[] { "ECDSA P384 SHA384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP384N, EcConstants.PublicKeyP384N, 96 },
    new object[] { "ECDSA P384 SHA512", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP384N, EcConstants.PublicKeyP384N, 96 },
    new object[] { "ECDSA P521 SHA256", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP521N, EcConstants.PublicKeyP521N, 132 },
    new object[] { "ECDSA P521 SHA384", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP521N, EcConstants.PublicKeyP521N, 132 },
    new object[] { "ECDSA P521 SHA512", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP521N, EcConstants.PublicKeyP521N, 132 },
  };
  
  [TestCaseSource(nameof(AsymConstCases))]
  public Task AsymConstVerify<TPublic,TPrivate>(string description, IKeyManagerImport<TPublic,TPrivate> importAlgo,
    string publicKeyData, string signature)
    where TPrivate : ISign where TPublic : IVerify =>
    base.AsymConstVerify(importAlgo, publicKeyData, signature);
  
  public static object[] AsymConstCases =
  {
    new object[] { "RSASSA-PKCS1-v1_5 256", Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Import, RsaConstants.PublicKey1, RsaConstants.SignatureKey1_Pkcs256 },
    new object[] { "RSA-PSS 256", Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import, RsaConstants.PublicKey2, RsaConstants.SignatureKey2_Native_Pss256 },
    new object[] { "RSA-PSS 512", Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Import, RsaConstants.PublicKey1, RsaConstants.SignatureKey1_Native_Pss512 },
    new object[] { "RSA-PSS 256", Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import, RsaConstants.PublicKey2, RsaConstants.SignatureKey2_Browser_Pss256 },
    new object[] { "RSA-PSS 512", Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Import, RsaConstants.PublicKey1, RsaConstants.SignatureKey1_Browser_Pss512 },
    new object[] { "ECDSA P256 SHA256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N256 },
    new object[] { "ECDSA P256 SHA384", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N384 },
    new object[] { "ECDSA P256 SHA512", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N512 },
    new object[] { "ECDSA P384 SHA256", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N256 },
    new object[] { "ECDSA P384 SHA384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N384 },
    new object[] { "ECDSA P384 SHA512", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N512 },
    new object[] { "ECDSA P521 SHA256", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N256 },
    new object[] { "ECDSA P521 SHA384", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N384 },
    new object[] { "ECDSA P521 SHA512", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N512 },
    new object[] { "ECDSA P256 SHA256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N256 },
    new object[] { "ECDSA P256 SHA384", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N384 },
    new object[] { "ECDSA P256 SHA512", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP256N, EcConstants.SignatureP256N512 },
    new object[] { "ECDSA P384 SHA256", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N256 },
    new object[] { "ECDSA P384 SHA384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N384 },
    new object[] { "ECDSA P384 SHA512", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP384N, EcConstants.SignatureP384N512 },
    new object[] { "ECDSA P521 SHA256", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N256 },
    new object[] { "ECDSA P521 SHA384", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N384 },
    new object[] { "ECDSA P521 SHA512", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP521N, EcConstants.SignatureP521N512 },
    new object[] { "ECDSA P256 SHA256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B256 },
    new object[] { "ECDSA P256 SHA384", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B384 },
    new object[] { "ECDSA P256 SHA512", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B512 },
    new object[] { "ECDSA P384 SHA256", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B256 },
    new object[] { "ECDSA P384 SHA384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B384 },
    new object[] { "ECDSA P384 SHA512", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B512 },
    new object[] { "ECDSA P521 SHA256", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B256 },
    new object[] { "ECDSA P521 SHA384", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B384 },
    new object[] { "ECDSA P521 SHA512", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B512 },
    new object[] { "ECDSA P256 SHA256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B256 },
    new object[] { "ECDSA P256 SHA384", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B384 },
    new object[] { "ECDSA P256 SHA512", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP256B, EcConstants.SignatureP256B512 },
    new object[] { "ECDSA P384 SHA256", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B256 },
    new object[] { "ECDSA P384 SHA384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B384 },
    new object[] { "ECDSA P384 SHA512", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP384B, EcConstants.SignatureP384B512 },
    new object[] { "ECDSA P521 SHA256", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B256 },
    new object[] { "ECDSA P521 SHA384", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B384 },
    new object[] { "ECDSA P521 SHA512", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PublicKeyP521B, EcConstants.SignatureP521B512 },
  };
}