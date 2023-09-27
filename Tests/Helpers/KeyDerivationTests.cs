using System.Text;

namespace FluentCrossPlatformCrypto.Tests.Helpers;

public class KeyDerivationTests
{
  protected IAssert Assert = null!;
  
  public async Task Ecdh(IKeyManagerImport<IEcVerifyExportPublic, IEcDeriveExportPrivate> algo, string keyA, string keyB, string expectedDerivation)
  {
    var privateA = await algo.Pkcs8(keyA.FromBase64());
    var publicA = await algo.Spki(await privateA.ExportSpki());
    var privateB = await algo.Pkcs8(keyB.FromBase64());
    var publicB = await algo.Spki(await privateB.ExportSpki());
    var derivationA = privateA.With(publicB);
    var derivationB = privateB.With(publicA);
    
    await CheckDerivation(expectedDerivation, derivationA, derivationB);
  }

  public async Task Pbkdf2(IDigest hash, uint iterations, string? salt, string expectedDerivation)
  {
    var keyA = await Algorithm.Pbkdf2[hash].Import.Text(MiscConstants.Message);
    var derivationA = keyA.With(iterations, salt?.FromBase64());

    var keyB = await Algorithm.Pbkdf2[hash].Import.Text(MiscConstants.Message);
    var derivationB = keyB.With(iterations, salt?.FromBase64());

    await CheckDerivation(expectedDerivation, derivationA, derivationB);
  }

  public async Task Hkdf(IDigest hash, string info, string? salt, string expectedDerivation)
  {
    var masterPassword = await GetMasterPasswordForHkdf(hash);
    // Console.WriteLine($"Master password={masterPassword.ToBase64()}");
    var hkdfA = await Algorithm.Hkdf[hash].Import.Raw(masterPassword);
    var derivationA = hkdfA.With(info, salt?.FromBase64());

    var hkdfB = await Algorithm.Hkdf[hash].Import.Raw(masterPassword);
    var derivationB = hkdfB.With(info, salt?.FromBase64());

    await CheckDerivation(expectedDerivation, derivationA, derivationB);
  }

  private async Task<byte[]> GetMasterPasswordForHkdf(IDigest hash)
  {
    var ecdh = Algorithm.Ec.P256.Dh[hash].Import;
    var privateA = await ecdh.Pkcs8(EcConstants.PrivateKeyP256N.FromBase64());
    var publicDataB = await (await ecdh.Pkcs8(EcConstants.PrivateKeyP256B.FromBase64())).ExportSpki();
    var publicB = await ecdh.Spki(publicDataB);
    var masterPassword = await privateA.With(publicB).Derive();
    return masterPassword;
  }
  
  private async Task CheckDerivation(string expectedDerivation, IDerive derivationA, IDerive derivationB)
  {
    var derivedA = await derivationA.Derive();
    // Console.WriteLine(derivedA.ToBase64());
    Assert.AreEqual(derivedA.ToBase64(), expectedDerivation);
    Assert.AreSameData(derivedA, await derivationB.Derive());

    var aesA = await derivationA.DeriveToAes();
    var aesB = await derivationB.DeriveToAes();
    Assert.AreEqual(await aesB.Decrypt(await aesA.Encrypt(MiscConstants.Message)), MiscConstants.Message);
    Assert.AreEqual(await aesA.Decrypt(await aesB.Encrypt(MiscConstants.Message)), MiscConstants.Message);

    var hmacA = await derivationA.DeriveToHmac();
    var hmacB = await derivationB.DeriveToHmac();
    var data = Encoding.UTF8.GetBytes(MiscConstants.Message);
    Assert.AreEqual(await hmacA.Verify(data, await hmacB.Sign(data)), true);
    Assert.AreEqual(await hmacB.Verify(data, await hmacA.Sign(data)), true);
  }

}