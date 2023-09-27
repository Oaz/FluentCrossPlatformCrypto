namespace FluentCrossPlatformCrypto.Tests.Helpers;

public abstract class EncryptDecryptTests
{
  protected IAssert Assert = null!;
  
  protected async Task SymEncryptDecrypt<T>(IKeyManagerImportRaw<T> importAlgo, string keyData, int expectedEncrypted)
    where T : IEncryptDecrypt
  {
    var key = await importAlgo.Raw(keyData.FromBase64());
    var encrypted = await key.Encrypt(MiscConstants.Message);
    Assert.AreEqual(encrypted.Length, expectedEncrypted);
    var clear = await key.Decrypt(encrypted);
    Assert.AreEqual(clear, MiscConstants.Message);
  }

  protected async Task SymConstDecrypt<T>(IKeyManagerImportRaw<T> importAlgo, string keyData, string encrypted)
    where T : IEncryptDecrypt
  {
    var key = await importAlgo.Raw(keyData.FromBase64());
    var clear = await key.Decrypt(encrypted.FromBase64());
    Assert.AreEqual(clear, MiscConstants.Message);
  }
  
  protected async Task AsymEncryptDecrypt<TPublic,TPrivate>(IKeyManagerImport<TPublic,TPrivate> importAlgo, string privateKeyData, string publicKeyData, int expectedEncrypted)
    where TPrivate : IDecrypt where TPublic : IEncrypt
  {
    var publicKey = await importAlgo.Spki(publicKeyData.FromBase64());
    var encrypted = await publicKey.Encrypt(MiscConstants.Message);
    Assert.AreEqual(encrypted.Length, expectedEncrypted);
    var privateKey = await importAlgo.Pkcs8(privateKeyData.FromBase64());
    var clear = await privateKey.Decrypt(encrypted);
    Assert.AreEqual(clear, MiscConstants.Message);
  }
  
  protected async Task AsymConstDecrypt<TPublic,TPrivate>(IKeyManagerImport<TPublic,TPrivate> importAlgo, string privateKeyData, string encrypted)
    where TPrivate : IDecrypt where TPublic : IEncrypt
  {
    var privateKey = await importAlgo.Pkcs8(privateKeyData.FromBase64());
    var clear = await privateKey.Decrypt(encrypted.FromBase64());
    Assert.AreEqual(clear, MiscConstants.Message);
  }


}