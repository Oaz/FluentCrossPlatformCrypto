using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Native;

public class ExportImportTests : Helpers.ExportImportTests
{
  [SetUp]
  public void Init()
  {
    Assert = new Asserts();
  }

  [TestCaseSource(nameof(RawCases))]
  public Task RawGen<T>(string description, IKeyManagerGenerate<T> genAlgo, IKeyManagerImportRaw<T> importAlgo,
    string constKey) where T : IExportRaw
    => base.RawGen(genAlgo, importAlgo);

  [TestCaseSource(nameof(RawCases))]
  public Task RawConst<T>(string description, IKeyManagerGenerate<T> genAlgo, IKeyManagerImportRaw<T> importAlgo,
    string constKey)
    where T : IExportRaw
    => base.RawConst(importAlgo, constKey);

  public static object[] RawCases =
  {
    new object[]
      { "AES-CBC 128", Algorithm.Aes.Cbc.Length128.Generate, Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc128 },
    new object[]
      { "AES-CBC 256", Algorithm.Aes.Cbc.Length256.Generate, Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc256 },
    new object[]
    {
      "HMAC SHA-256", Algorithm.Hmac[Algorithm.Digest.Sha256].Generate, Algorithm.Hmac[Algorithm.Digest.Sha256].Import,
      HmacConstants.Key256
    },
    new object[]
    {
      "HMAC SHA-512", Algorithm.Hmac[Algorithm.Digest.Sha512].Generate, Algorithm.Hmac[Algorithm.Digest.Sha512].Import,
      HmacConstants.Key512
    },
  };

  [TestCaseSource(nameof(AsymCases))]
  public Task PublicPrivateKey<TPublic, TPrivate>(string description,
    IKeyManagerGenerate<IKeyPair<TPublic, TPrivate>> genAlgo, IKeyManagerImport<TPublic, TPrivate> importAlgo)
    where TPrivate : IExportPrivate where TPublic : IExportPublic
    => base.PublicPrivateKey(genAlgo, importAlgo);

  public static object[] AsymCases =
  {
    new object[]
    {
      "RSA-OAEP 2048", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Generate[2048],
      Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import
    },
    new object[]
    {
      "RSA-OAEP 4096", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Generate[4096],
      Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import
    },
    new object[]
    {
      "RSA-PSS", Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Generate[2048],
      Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import
    },
    new object[]
    {
      "RSASSA-PKCS1-v1_5", Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Generate[2048],
      Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Import
    },
    new object[]
    {
      "ECDSA P256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Generate,
      Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import
    },
    new object[]
    {
      "ECDSA P384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Generate,
      Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Import
    },
    new object[]
    {
      "ECDSA P521", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Generate,
      Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import
    },
  };

  [TestCaseSource(nameof(AsymConstCases))]
  public Task ConstPublicPrivateKey<TPublic, TPrivate>(string description,
    IKeyManagerImport<TPublic, TPrivate> importAlgo, string privateData, string publicData)
    where TPrivate : IExportPrivate where TPublic : IExportPublic
    => base.ConstPublicPrivateKey(importAlgo, privateData, publicData);

  public static object[] AsymConstCases =
  {
    new object[]
    {
      "RSA-OAEP", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1
    },
    new object[]
    {
      "RSA-OAEP", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.PublicKey2
    },
    new object[]
    {
      "ECDSA P256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP256N,
      EcConstants.PublicKeyP256N
    },
    new object[]
    {
      "ECDSA P384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP384N,
      EcConstants.PublicKeyP384N
    },
    new object[]
    {
      "ECDSA P521", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP521N,
      EcConstants.PublicKeyP521N
    },
    new object[]
    {
      "ECDSA P256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP256B,
      EcConstants.PublicKeyP256B
    },
    new object[]
    {
      "ECDSA P384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP384B,
      EcConstants.PublicKeyP384B
    },
    new object[]
    {
      "ECDSA P521", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP521B,
      EcConstants.PublicKeyP521B
    },
  };
}