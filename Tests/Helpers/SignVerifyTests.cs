using System.Text;

namespace FluentCrossPlatformCrypto.Tests.Helpers;

public class SignVerifyTests
{
  protected IAssert Assert = null!;

  protected async Task SymSignVerify<T>(IKeyManagerImportRaw<T> importAlgo,
    string keyData, int expectedSignature)
    where T : ISign, IVerify
  {
    var key = await importAlgo.Raw(keyData.FromBase64());
    var message = Encoding.UTF8.GetBytes(MiscConstants.Message);
    var signature = await key.Sign(message);
    // Console.WriteLine(signature.ToBase64());
    Assert.AreEqual(signature.Length, expectedSignature);
    Assert.AreEqual(await key.Verify(message, signature), true);
    Assert.AreEqual(await key.Verify(Encoding.UTF8.GetBytes(MiscConstants.Message+"Whatever"), signature), false);
  }
  
  protected async Task SymConstVerify<T>(IKeyManagerImportRaw<T> importAlgo, string keyData, string signature)
    where T : ISign, IVerify
  {
    var key = await importAlgo.Raw(keyData.FromBase64());
    var message = Encoding.UTF8.GetBytes(MiscConstants.Message);
    Assert.AreEqual(await key.Verify(message, signature.FromBase64()), true);
    Assert.AreEqual(await key.Verify(Encoding.UTF8.GetBytes(MiscConstants.Message+"Whatever"), signature.FromBase64()), false);
  }

  protected async Task AsymSignVerify<TPublic, TPrivate>(IKeyManagerImport<TPublic, TPrivate> importAlgo,
    string privateKeyData, string publicKeyData, int expectedSignature)
    where TPrivate : ISign where TPublic : IVerify
  {
    var message = Encoding.UTF8.GetBytes(MiscConstants.Message);
    var privateKey = await importAlgo.Pkcs8(privateKeyData.FromBase64());
    var signature = await privateKey.Sign(message);
    // Console.WriteLine(signature.ToBase64());
    Assert.AreEqual(signature.Length, expectedSignature);
    var publicKey = await importAlgo.Spki(publicKeyData.FromBase64());
    Assert.AreEqual(await publicKey.Verify(message, signature), true);
    Assert.AreEqual(await publicKey.Verify(Encoding.UTF8.GetBytes(MiscConstants.Message+"Whatever"), signature), false);
  }
  
  protected async Task AsymConstVerify<TPublic,TPrivate>(IKeyManagerImport<TPublic,TPrivate> importAlgo, string publicKeyData, string signature)
    where TPrivate : ISign where TPublic : IVerify
  {
    var message = Encoding.UTF8.GetBytes(MiscConstants.Message);
    var publicKey = await importAlgo.Spki(publicKeyData.FromBase64());
    Assert.AreEqual(await publicKey.Verify(message, signature.FromBase64()), true);
    Assert.AreEqual(await publicKey.Verify(Encoding.UTF8.GetBytes(MiscConstants.Message+"Whatever"), signature.FromBase64()), false);
  }
}