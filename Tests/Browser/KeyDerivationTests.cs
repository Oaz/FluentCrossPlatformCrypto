using FluentCrossPlatformCrypto.Tests.Browser.TestFramework;
using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Browser;

public class KeyDerivationTests : Helpers.KeyDerivationTests
{
  public void Add(Suite suite)
  {
    Assert = new Assert();
    
    TestEcdh( "P256 SHA256", Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP256N, EcConstants.PrivateKeyP256B, EcConstants.ExpectedEcdhP256Sha256 );
    TestEcdh( "P256 SHA384", Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP256N, EcConstants.PrivateKeyP256B, EcConstants.ExpectedEcdhP256Sha384 );
    TestEcdh( "P256 SHA512", Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP256N, EcConstants.PrivateKeyP256B, EcConstants.ExpectedEcdhP256Sha512 );
    TestEcdh( "P384 SHA256", Algorithm.Ec.P384.Dh[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP384N, EcConstants.PrivateKeyP384B, EcConstants.ExpectedEcdhP384Sha256 );
    TestEcdh( "P384 SHA384", Algorithm.Ec.P384.Dh[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP384N, EcConstants.PrivateKeyP384B, EcConstants.ExpectedEcdhP384Sha384 );
    TestEcdh( "P384 SHA512", Algorithm.Ec.P384.Dh[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP384N, EcConstants.PrivateKeyP384B, EcConstants.ExpectedEcdhP384Sha512 );
    TestEcdh( "P521 SHA256", Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha256].Import, EcConstants.PrivateKeyP521N, EcConstants.PrivateKeyP521B, EcConstants.ExpectedEcdhP521Sha256 );
    TestEcdh( "P521 SHA384", Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha384].Import, EcConstants.PrivateKeyP521N, EcConstants.PrivateKeyP521B, EcConstants.ExpectedEcdhP521Sha384 );
    TestEcdh( "P521 SHA512", Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha512].Import, EcConstants.PrivateKeyP521N, EcConstants.PrivateKeyP521B, EcConstants.ExpectedEcdhP521Sha512 );

    void TestEcdh(string description, IKeyManagerImport<IEcVerifyExportPublic, IEcDeriveExportPrivate> importAlgo,
      string keyDataA, string keyDataB, string expectedDerivation) =>
      suite.Test($"ECDH {description}", () => base.Ecdh(importAlgo, keyDataA, keyDataB, expectedDerivation));

    TestHkdf( "SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info0, MiscConstants.Salt0, HkdfConstants.ExpectedSha256Info0Salt0 );
    TestHkdf( "SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info1, MiscConstants.Salt0, HkdfConstants.ExpectedSha256Info1Salt0 );
    TestHkdf( "SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info1, MiscConstants.SaltX, HkdfConstants.ExpectedSha256Info1SaltX );
    TestHkdf( "SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info1, MiscConstants.SaltY, HkdfConstants.ExpectedSha256Info1SaltY );
    TestHkdf( "SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info2, MiscConstants.Salt0, HkdfConstants.ExpectedSha256Info2Salt0 );
    TestHkdf( "SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info2, MiscConstants.SaltX, HkdfConstants.ExpectedSha256Info2SaltX );
    TestHkdf( "SHA256", Algorithm.Digest.Sha256, HkdfConstants.Info2, MiscConstants.SaltY, HkdfConstants.ExpectedSha256Info2SaltY );
    
    TestHkdf( "SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info0, MiscConstants.Salt0, HkdfConstants.ExpectedSha384Info0Salt0 );
    TestHkdf( "SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info1, MiscConstants.Salt0, HkdfConstants.ExpectedSha384Info1Salt0 );
    TestHkdf( "SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info1, MiscConstants.SaltX, HkdfConstants.ExpectedSha384Info1SaltX );
    TestHkdf( "SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info1, MiscConstants.SaltY, HkdfConstants.ExpectedSha384Info1SaltY );
    TestHkdf( "SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info2, MiscConstants.Salt0, HkdfConstants.ExpectedSha384Info2Salt0 );
    TestHkdf( "SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info2, MiscConstants.SaltX, HkdfConstants.ExpectedSha384Info2SaltX );
    TestHkdf( "SHA384", Algorithm.Digest.Sha384, HkdfConstants.Info2, MiscConstants.SaltY, HkdfConstants.ExpectedSha384Info2SaltY );

    TestHkdf( "SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info0, MiscConstants.Salt0, HkdfConstants.ExpectedSha512Info0Salt0 );
    TestHkdf( "SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info1, MiscConstants.Salt0, HkdfConstants.ExpectedSha512Info1Salt0 );
    TestHkdf( "SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info1, MiscConstants.SaltX, HkdfConstants.ExpectedSha512Info1SaltX );
    TestHkdf( "SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info1, MiscConstants.SaltY, HkdfConstants.ExpectedSha512Info1SaltY );
    TestHkdf( "SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info2, MiscConstants.Salt0, HkdfConstants.ExpectedSha512Info2Salt0 );
    TestHkdf( "SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info2, MiscConstants.SaltX, HkdfConstants.ExpectedSha512Info2SaltX );
    TestHkdf( "SHA512", Algorithm.Digest.Sha512, HkdfConstants.Info2, MiscConstants.SaltY, HkdfConstants.ExpectedSha512Info2SaltY );

    void TestHkdf(string description, IDigest hash, string info, string? salt, string expectedDerivation) =>
      suite.Test($"HKDF {description}", () => base.Hkdf(hash, info, salt, expectedDerivation));

    TestPbkdf2( "SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration1, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha256Iteration1Salt0 );
    TestPbkdf2( "SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration1, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha256Iteration1SaltX );
    TestPbkdf2( "SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration1, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha256Iteration1SaltY );
    TestPbkdf2( "SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration2, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha256Iteration2Salt0 );
    TestPbkdf2( "SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration2, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha256Iteration2SaltX );
    TestPbkdf2( "SHA256", Algorithm.Digest.Sha256, Pbkdf2Constants.Iteration2, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha256Iteration2SaltY );
    
    TestPbkdf2( "SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration1, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha384Iteration1Salt0 );
    TestPbkdf2( "SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration1, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha384Iteration1SaltX );
    TestPbkdf2( "SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration1, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha384Iteration1SaltY );
    TestPbkdf2( "SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration2, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha384Iteration2Salt0 );
    TestPbkdf2( "SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration2, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha384Iteration2SaltX );
    TestPbkdf2( "SHA384", Algorithm.Digest.Sha384, Pbkdf2Constants.Iteration2, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha384Iteration2SaltY );

    TestPbkdf2( "SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration1, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha512Iteration1Salt0 );
    TestPbkdf2( "SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration1, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha512Iteration1SaltX );
    TestPbkdf2( "SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration1, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha512Iteration1SaltY );
    TestPbkdf2( "SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration2, MiscConstants.Salt0, Pbkdf2Constants.ExpectedSha512Iteration2Salt0 );
    TestPbkdf2( "SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration2, MiscConstants.SaltX, Pbkdf2Constants.ExpectedSha512Iteration2SaltX );
    TestPbkdf2( "SHA512", Algorithm.Digest.Sha512, Pbkdf2Constants.Iteration2, MiscConstants.SaltY, Pbkdf2Constants.ExpectedSha512Iteration2SaltY );

    void TestPbkdf2(string description, IDigest hash, uint iterations, string? salt, string expectedDerivation) =>
      suite.Test($"PBKDF2 {description}", () => base.Pbkdf2(hash, iterations, salt, expectedDerivation));

  }
}