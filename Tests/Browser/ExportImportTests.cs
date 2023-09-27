using FluentCrossPlatformCrypto.Tests.Browser.TestFramework;
using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Browser;

public class ExportImportTests : Helpers.ExportImportTests
{
  public void Add(Suite suite)
  {
    Assert = new Assert();

    TestRaw("AES-CBC 128", Algorithm.Aes.Cbc.Length128.Generate, Algorithm.Aes.Cbc.Import);
    TestRaw("AES-CBC 256", Algorithm.Aes.Cbc.Length256.Generate, Algorithm.Aes.Cbc.Import);
    TestRaw("AES-CTR", Algorithm.Aes.Ctr.Length256.Generate, Algorithm.Aes.Cbc.Import);
    TestRaw("AES-GCM", Algorithm.Aes.Gcm.Length256.Generate, Algorithm.Aes.Cbc.Import);
    TestRaw("HMAC SHA-256", Algorithm.Hmac[Algorithm.Digest.Sha256].Generate, Algorithm.Hmac[Algorithm.Digest.Sha256].Import);
    TestRaw("HMAC SHA-512", Algorithm.Hmac[Algorithm.Digest.Sha512].Generate, Algorithm.Hmac[Algorithm.Digest.Sha512].Import);

    void TestRaw<T>(string description, IKeyManagerGenerate<T> genAlgo, IKeyManagerImportRaw<T> importAlgo)
      where T : IExportRaw =>
      suite.Test($"Export Import {description}", () => RawGen(genAlgo, importAlgo));

    TestRawConst("AES-CBC 128", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc128);
    TestRawConst("AES-CBC 256", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc256);
    TestRawConst("HMAC SHA-256", Algorithm.Hmac[Algorithm.Digest.Sha256].Import, HmacConstants.Key256);
    TestRawConst("HMAC SHA-512", Algorithm.Hmac[Algorithm.Digest.Sha512].Import, HmacConstants.Key512);

    void TestRawConst<T>(string description, IKeyManagerImportRaw<T> importAlgo, string constKey)
      where T : IExportRaw =>
      suite.Test($"Import const Export {description}", () => base.RawConst<T>(importAlgo, constKey));

    TestPublicPrivateKey("RSA-OAEP 2048", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Generate[2048], Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import);
    TestPublicPrivateKey("RSA-OAEP 4096", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Generate[4096], Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import);
    TestPublicPrivateKey("RSA-PSS", Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Generate[2048], Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import);
    TestPublicPrivateKey("RSASSA-PKCS1-v1_5", Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Generate[2048], Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Import);
    TestPublicPrivateKey("ECDSA P256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Generate, Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import);
    TestPublicPrivateKey("ECDSA P384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha384].Generate, Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import);
    TestPublicPrivateKey("ECDSA P521", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha512].Generate, Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import);

    void TestPublicPrivateKey<TPublic, TPrivate>(string description,
      IKeyManagerGenerate<IKeyPair<TPublic, TPrivate>> genAlgo, IKeyManagerImport<TPublic, TPrivate> importAlgo)
      where TPrivate : IExportPrivate where TPublic : IExportPublic =>
      suite.Test($"Export Import {description}", () => base.PublicPrivateKey<TPublic, TPrivate>(genAlgo, importAlgo));

    TestConstPublicPrivateKey("RSA-OAEP", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1);
    TestConstPublicPrivateKey("RSA-OAEP", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.PublicKey2);
    TestConstPublicPrivateKey("ECDSA P256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP256N, EcConstants.PublicKeyP256N);
    TestConstPublicPrivateKey("ECDSA P384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP384N, EcConstants.PublicKeyP384N);
    TestConstPublicPrivateKey("ECDSA P521", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP521N, EcConstants.PublicKeyP521N);
    TestConstPublicPrivateKey("ECDSA P256", Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP256B, EcConstants.PublicKeyP256B);
    TestConstPublicPrivateKey("ECDSA P384", Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP384B, EcConstants.PublicKeyP384B);
    TestConstPublicPrivateKey("ECDSA P521", Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP521B, EcConstants.PublicKeyP521B);

    void TestConstPublicPrivateKey<TPublic, TPrivate>(string description,
      IKeyManagerImport<TPublic, TPrivate> importAlgo, string privateData, string publicData)
      where TPrivate : IExportPrivate where TPublic : IExportPublic =>
      suite.Test($"Import const Export {description}",
        () => base.ConstPublicPrivateKey<TPublic, TPrivate>(importAlgo, privateData, publicData));
  }
}