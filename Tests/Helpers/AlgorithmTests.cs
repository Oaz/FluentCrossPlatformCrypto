namespace FluentCrossPlatformCrypto.Tests.Helpers;

public class AlgorithmTests
{
  protected IAssert Assert = null!;

  public static object[][] Examples =
  {
    new object[] { Algorithm.Digest.Sha1, typeof(IDigest) },
    new object[] { Algorithm.Digest.Sha256, typeof(IDigest) },
    new object[] { Algorithm.Digest.Sha384, typeof(IDigest) },
    new object[] { Algorithm.Digest.Sha512, typeof(IDigest) },

    new object[] { Algorithm.Hmac[Algorithm.Digest.Sha256].Generate, typeof(IKeyManagerGenerate<ISignVerify>) },
    new object[] { Algorithm.Hmac[Algorithm.Digest.Sha384].Generate, typeof(IKeyManagerGenerate<ISignVerify>) },
    new object[] { Algorithm.Hmac[Algorithm.Digest.Sha512].Generate, typeof(IKeyManagerGenerate<ISignVerify>) },
    new object[] { Algorithm.Hmac[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImportRaw<ISignVerify>) },
    new object[] { Algorithm.Hmac[Algorithm.Digest.Sha384].Import, typeof(IKeyManagerImportRaw<ISignVerify>) },
    new object[] { Algorithm.Hmac[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImportRaw<ISignVerify>) },
    
    new object[] { Algorithm.Hkdf[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImportRaw<IDeriveHkdf>) },
    new object[] { Algorithm.Hkdf[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImportRaw<IDeriveHkdf>) },
    new object[] { Algorithm.Hkdf[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImportRaw<IDeriveHkdf>) },
    
    new object[] { Algorithm.Pbkdf2[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImportText<IDerivePbkdf2>) },
    new object[] { Algorithm.Pbkdf2[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImportText<IDerivePbkdf2>) },
    new object[] { Algorithm.Pbkdf2[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImportText<IDerivePbkdf2>) },

    new object[] { Algorithm.Aes.Cbc.Import, typeof(IKeyManagerImportRaw<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Cbc.Length128.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Cbc.Length192.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Cbc.Length256.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Ctr.Import, typeof(IKeyManagerImportRaw<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Ctr.Length128.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Ctr.Length192.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Ctr.Length256.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Gcm.Import, typeof(IKeyManagerImportRaw<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Gcm.Length128.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Gcm.Length192.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    new object[] { Algorithm.Aes.Gcm.Length256.Generate, typeof(IKeyManagerGenerate<IEncryptDecrypt>) },
    
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IEncryptExport, IDecryptExport>>) },
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IEncryptExport, IDecryptExport>>) },
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha384].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IEncryptExport, IDecryptExport>>) },
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha384].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IEncryptExport, IDecryptExport>>) },
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IEncryptExport, IDecryptExport>>) },
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IEncryptExport, IDecryptExport>>) },
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IEncryptExport, IDecryptExport>) },
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha384].Import, typeof(IKeyManagerImport<IEncryptExport, IDecryptExport>) },
    new object[] { Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImport<IEncryptExport, IDecryptExport>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha384].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha384].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha512].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha512].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IVerifyExportPublic, ISignExportPrivate>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha384].Import, typeof(IKeyManagerImport<IVerifyExportPublic, ISignExportPrivate>) },
    new object[] { Algorithm.Rsa.SsaPkcs1V15[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImport<IVerifyExportPublic, ISignExportPrivate>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha384].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha384].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Generate[2048], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Generate[4096], typeof(IKeyManagerGenerate<IKeyPair<IVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IVerifyExportPublic, ISignExportPrivate>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha384].Import, typeof(IKeyManagerImport<IVerifyExportPublic, ISignExportPrivate>) },
    new object[] { Algorithm.Rsa.Pss[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImport<IVerifyExportPublic, ISignExportPrivate>) },
    
    new object[] { Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Generate, typeof(IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IEcVerifyExportPublic, ISignExportPrivate>) },
    new object[] { Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Generate, typeof(IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Ec.P256.Dsa[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImport<IEcVerifyExportPublic, ISignExportPrivate>) },
    new object[] { Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Generate, typeof(IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Ec.P384.Dsa[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IEcVerifyExportPublic, ISignExportPrivate>) },
    new object[] { Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Generate, typeof(IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, ISignExportPrivate>>) },
    new object[] { Algorithm.Ec.P521.Dsa[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IEcVerifyExportPublic, ISignExportPrivate>) },
    
    new object[] { Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha256].Generate, typeof(IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, IEcDeriveExportPrivate>>) },
    new object[] { Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IEcVerifyExportPublic, IEcDeriveExportPrivate>) },
    new object[] { Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha512].Generate, typeof(IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, IEcDeriveExportPrivate>>) },
    new object[] { Algorithm.Ec.P256.Dh[Algorithm.Digest.Sha512].Import, typeof(IKeyManagerImport<IEcVerifyExportPublic, IEcDeriveExportPrivate>) },
    new object[] { Algorithm.Ec.P384.Dh[Algorithm.Digest.Sha256].Generate, typeof(IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, IEcDeriveExportPrivate>>) },
    new object[] { Algorithm.Ec.P384.Dh[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IEcVerifyExportPublic, IEcDeriveExportPrivate>) },
    new object[] { Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha256].Generate, typeof(IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, IEcDeriveExportPrivate>>) },
    new object[] { Algorithm.Ec.P521.Dh[Algorithm.Digest.Sha256].Import, typeof(IKeyManagerImport<IEcVerifyExportPublic, IEcDeriveExportPrivate>) },

  };
}