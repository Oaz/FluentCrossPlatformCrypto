namespace FluentCrossPlatformCrypto.Tests.Helpers;

public abstract class ExportImportTests
{
  protected IAssert Assert = null!;

  protected async Task RawGen<T>(IKeyManagerGenerate<T> genAlgo, IKeyManagerImportRaw<T> importAlgo)
    where T : IExportRaw
  {
    var key = await genAlgo.Key();
    var rawKeyData = await key.ExportRaw();
    var key2 = await importAlgo.Raw(rawKeyData);
    Assert.AreSameData(await key2.ExportRaw(), rawKeyData);
  }

  protected async Task RawConst<T>(IKeyManagerImportRaw<T> importAlgo, string constKey)
    where T : IExportRaw
  {
    var rawKeyData = constKey.FromBase64();
    var key = await importAlgo.Raw(rawKeyData);
    Assert.AreSameData(await key.ExportRaw(), rawKeyData);
  }
  
  protected async Task PublicPrivateKey<TPublic, TPrivate>(
    IKeyManagerGenerate<IKeyPair<TPublic, TPrivate>> genAlgo, IKeyManagerImport<TPublic, TPrivate> importAlgo)
    where TPrivate : IExportPrivate where TPublic : IExportPublic
  {
    var key = await genAlgo.Key();
    var privateKeyData = await key.PrivateKey.ExportPkcs8();
    // Console.WriteLine(privateKeyData.ToBase64());
    var privateKey = await importAlgo.Pkcs8(privateKeyData);
    Assert.AreSameData(await privateKey.ExportPkcs8(),privateKeyData);
    var publicKeyData = await key.PublicKey.ExportSpki();
    // Console.WriteLine(publicKeyData.ToBase64());
    var publicKey = await importAlgo.Spki(publicKeyData);
    Assert.AreSameData(await publicKey.ExportSpki(), publicKeyData);
  }
  
  protected async Task ConstPublicPrivateKey<TPublic, TPrivate>(
    IKeyManagerImport<TPublic, TPrivate> importAlgo, string privateKeyData, string publicKeyData)
    where TPrivate : IExportPrivate where TPublic : IExportPublic
  {
    var privateKey = await importAlgo.Pkcs8(privateKeyData.FromBase64());
    Assert.AreSameData(await privateKey.ExportPkcs8(),privateKeyData.FromBase64());
    Assert.AreSameData(await privateKey.ExportSpki(), publicKeyData.FromBase64());
    var publicKey = await importAlgo.Spki(publicKeyData.FromBase64());
    Assert.AreSameData(await publicKey.ExportSpki(), publicKeyData.FromBase64());
  }
  
}