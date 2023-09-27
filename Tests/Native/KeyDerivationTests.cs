using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Native;

public class KeyDerivationTests : Helpers.KeyDerivationTests
{
  [SetUp]
  public void Init()
  {
    Assert = new Asserts();
  }
  
  [TestCaseSource(nameof(EcdhCases))]
  public Task Ecdh(string description, IKeyManagerImport<IEcVerifyExportPublic, IEcDeriveExportPrivate> importAlgo,
    string keyDataA, string keyDataB, string expectedDerivation) =>
    base.Ecdh(importAlgo, keyDataA, keyDataB, expectedDerivation);
  
  public static object[] EcdhCases =
  {
    new object[] { "ECDSA P256 SHA256", Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP256N, EcConstants.PrivateKeyP256B, EcConstants.ExpectedEcdhP256Sha256 },
    new object[] { "ECDSA P256 SHA384", Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP256N, EcConstants.PrivateKeyP256B, EcConstants.ExpectedEcdhP256Sha384 },
    new object[] { "ECDSA P256 SHA512", Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP256N, EcConstants.PrivateKeyP256B, EcConstants.ExpectedEcdhP256Sha512 },
    new object[] { "ECDSA P384 SHA256", Algorithm.Ec.P384.Dh[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP384N, EcConstants.PrivateKeyP384B, EcConstants.ExpectedEcdhP384Sha256 },
    new object[] { "ECDSA P384 SHA384", Algorithm.Ec.P384.Dh[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP384N, EcConstants.PrivateKeyP384B, EcConstants.ExpectedEcdhP384Sha384 },
    new object[] { "ECDSA P384 SHA512", Algorithm.Ec.P384.Dh[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP384N, EcConstants.PrivateKeyP384B, EcConstants.ExpectedEcdhP384Sha512 },
    new object[] { "ECDSA P521 SHA256", Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP521N, EcConstants.PrivateKeyP521B, EcConstants.ExpectedEcdhP521Sha256 },
    new object[] { "ECDSA P521 SHA384", Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP521N, EcConstants.PrivateKeyP521B, EcConstants.ExpectedEcdhP521Sha384 },
    new object[] { "ECDSA P521 SHA512", Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP521N, EcConstants.PrivateKeyP521B, EcConstants.ExpectedEcdhP521Sha512 },
  };
  
  [TestCaseSource(nameof(HkdfCases))]
  public Task Hkdf(string description, IDigest hash, string info, string? salt, string expectedDerivation) =>
    base.Hkdf(hash, info, salt, expectedDerivation);
  
  public static object[] HkdfCases =
  {
    new object[] { "HKDF SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info0, MiscConstants.Salt0, HkdfConstants.ExpectedSha256Info0Salt0 },
    new object[] { "HKDF SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info1, MiscConstants.Salt0, HkdfConstants.ExpectedSha256Info1Salt0 },
    new object[] { "HKDF SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info1, MiscConstants.SaltX, HkdfConstants.ExpectedSha256Info1SaltX },
    new object[] { "HKDF SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info1, MiscConstants.SaltY, HkdfConstants.ExpectedSha256Info1SaltY },
    new object[] { "HKDF SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info2, MiscConstants.Salt0, HkdfConstants.ExpectedSha256Info2Salt0 },
    new object[] { "HKDF SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info2, MiscConstants.SaltX, HkdfConstants.ExpectedSha256Info2SaltX },
    new object[] { "HKDF SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info2, MiscConstants.SaltY, HkdfConstants.ExpectedSha256Info2SaltY },

    new object[] { "HKDF SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info0, MiscConstants.Salt0, HkdfConstants.ExpectedSha384Info0Salt0 },
    new object[] { "HKDF SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info1, MiscConstants.Salt0, HkdfConstants.ExpectedSha384Info1Salt0 },
    new object[] { "HKDF SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info1, MiscConstants.SaltX, HkdfConstants.ExpectedSha384Info1SaltX },
    new object[] { "HKDF SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info1, MiscConstants.SaltY, HkdfConstants.ExpectedSha384Info1SaltY },
    new object[] { "HKDF SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info2, MiscConstants.Salt0, HkdfConstants.ExpectedSha384Info2Salt0 },
    new object[] { "HKDF SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info2, MiscConstants.SaltX, HkdfConstants.ExpectedSha384Info2SaltX },
    new object[] { "HKDF SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info2, MiscConstants.SaltY, HkdfConstants.ExpectedSha384Info2SaltY },

    new object[] { "HKDF SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info0, MiscConstants.Salt0, HkdfConstants.ExpectedSha512Info0Salt0 },
    new object[] { "HKDF SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info1, MiscConstants.Salt0, HkdfConstants.ExpectedSha512Info1Salt0 },
    new object[] { "HKDF SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info1, MiscConstants.SaltX, HkdfConstants.ExpectedSha512Info1SaltX },
    new object[] { "HKDF SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info1, MiscConstants.SaltY, HkdfConstants.ExpectedSha512Info1SaltY },
    new object[] { "HKDF SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info2, MiscConstants.Salt0, HkdfConstants.ExpectedSha512Info2Salt0 },
    new object[] { "HKDF SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info2, MiscConstants.SaltX, HkdfConstants.ExpectedSha512Info2SaltX },
    new object[] { "HKDF SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info2, MiscConstants.SaltY, HkdfConstants.ExpectedSha512Info2SaltY },
  };
  
  [TestCaseSource(nameof(Pbkdf2Cases))]
  public Task Pbkdf2(string description, IDigest hash, uint iterations, string? salt, string expectedDerivation) =>
    base.Pbkdf2(hash, iterations, salt, expectedDerivation);
  
  public static object[] Pbkdf2Cases =
  {
    new object[] { "PBKDF2 SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration1, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha256Iteration1Salt0 },
    new object[] { "PBKDF2 SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration1, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha256Iteration1SaltX },
    new object[] { "PBKDF2 SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration1, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha256Iteration1SaltY },
    new object[] { "PBKDF2 SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration2, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha256Iteration2Salt0 },
    new object[] { "PBKDF2 SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration2, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha256Iteration2SaltX },
    new object[] { "PBKDF2 SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration2, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha256Iteration2SaltY },

    new object[] { "PBKDF2 SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration1, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha384Iteration1Salt0 },
    new object[] { "PBKDF2 SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration1, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha384Iteration1SaltX },
    new object[] { "PBKDF2 SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration1, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha384Iteration1SaltY },
    new object[] { "PBKDF2 SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration2, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha384Iteration2Salt0 },
    new object[] { "PBKDF2 SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration2, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha384Iteration2SaltX },
    new object[] { "PBKDF2 SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration2, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha384Iteration2SaltY },

    new object[] { "PBKDF2 SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration1, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha512Iteration1Salt0 },
    new object[] { "PBKDF2 SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration1, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha512Iteration1SaltX },
    new object[] { "PBKDF2 SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration1, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha512Iteration1SaltY },
    new object[] { "PBKDF2 SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration2, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha512Iteration2Salt0 },
    new object[] { "PBKDF2 SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration2, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha512Iteration2SaltX },
    new object[] { "PBKDF2 SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration2, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha512Iteration2SaltY },
  };
}