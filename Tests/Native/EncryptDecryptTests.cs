using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Native;

public class EncryptDecryptTests : Helpers.EncryptDecryptTests
{
  [SetUp]
  public void Init()
  {
    Assert = new Asserts();
  }

  [TestCaseSource(nameof(AesCases))]
  public Task SymEncryptDecrypt<T>(string description, IKeyManagerImportRaw<T> importAlgo, string keyData,
    int expectedEncrypted, string encrypted)
    where T : IEncryptDecrypt => base.SymEncryptDecrypt(importAlgo, keyData, expectedEncrypted);

  [TestCaseSource(nameof(AesCases))]
  public Task SymConstDecrypt<T>(string description, IKeyManagerImportRaw<T> importAlgo, string keyData,
    int expectedEncrypted, string encrypted)
    where T : IEncryptDecrypt => base.SymConstDecrypt(importAlgo, keyData, encrypted);

  public static object[] AesCases =
  {
    new object[] { "AES-CBC 128", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc128, 80, AesConstants.EncryptedCbc128A },
    new object[] { "AES-CBC 128", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc128, 80, AesConstants.EncryptedCbc128B },
    new object[] { "AES-CBC 256", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc256, 80, AesConstants.EncryptedCbc256A },
    new object[] { "AES-CBC 256", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc256, 80, AesConstants.EncryptedCbc256B }
  };
  
  [TestCaseSource(nameof(AsymCases))]
  public Task AsymEncryptDecrypt<TPublic,TPrivate>(string description, IKeyManagerImport<TPublic,TPrivate> importAlgo,
    string privateKeyData, string publicKeyData, int expectedEncrypted)
    where TPrivate : IDecrypt where TPublic : IEncrypt =>
    base.AsymEncryptDecrypt(importAlgo, privateKeyData, publicKeyData, expectedEncrypted);
  
  public static object[] AsymCases =
  {
    new object[] { "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1, 256 },
    new object[] { "RSA-OAEP 512", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1, 256 },
    new object[] { "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.PublicKey2, 256 },
  };
    
  [TestCaseSource(nameof(AsymConstCases))]
  public Task AsymConstDecrypt<TPublic,TPrivate>(string description, IKeyManagerImport<TPublic,TPrivate> importAlgo,
    string privateKeyData, string encrypted)
    where TPrivate : IDecrypt where TPublic : IEncrypt =>
    base.AsymConstDecrypt(importAlgo, privateKeyData, encrypted);

  public static object[] AsymConstCases =
  {
    new object[] { "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.EncryptedKey1_Native_256 },
    new object[] { "RSA-OAEP 512", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Import, RsaConstants.PrivateKey1, RsaConstants.EncryptedKey1_Native_512 },
    new object[] { "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.EncryptedKey2_Native_256 },
    new object[] { "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.EncryptedKey1_Browser_256 },
    new object[] { "RSA-OAEP 512", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Import, RsaConstants.PrivateKey1, RsaConstants.EncryptedKey1_Browser_512 },
    new object[] { "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.EncryptedKey2_Browser_256 },
  };

}