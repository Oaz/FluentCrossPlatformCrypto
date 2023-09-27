using System.Dynamic;
using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using System.Text;

namespace FluentCrossPlatformCrypto.Internals.Browser;

[SupportedOSPlatform("browser")]
internal class Key :
  IEncryptDecrypt, IEncryptExport, IDecryptExport,
  ISignExportPrivate, IEcVerifyExportPublic, ISignVerify, IEcDeriveExportPrivate,
  IDeriveHkdf, IDerivePbkdf2
{
  protected readonly JSObject JsKey;
  internal readonly ExpandoObject Algorithm;
  protected readonly BrowserEngine Engine;

  public Key(JSObject key, KeyType type, ExpandoObject algorithm, BrowserEngine engine)
  {
    JsKey = key;
    Algorithm = algorithm;
    Engine = engine;
    Type = type;
  }
  
  public KeyType Type { get; }

  public async Task<byte[]> Encrypt(string message)
  {
    var e = Engine.GetEncryption(this);
    var algo = e.BeforeEncrypt(this);
    var msg = Interop.FromUint8Array(Encoding.UTF8.GetBytes(message));
    var result = await Interop.Encrypt(Engine.ToJsObject(algo), JsKey, msg);
    var encrypted = Interop.ToUint8Array(result);
    return e.AfterEncrypt(algo, encrypted);
  }

  public async Task<string> Decrypt(byte[] data)
  {
    var (algo, encrypted) = Engine.GetEncryption(this).BeforeDecrypt(this, data);
    var result = await Interop.Decrypt(Engine.ToJsObject(algo), JsKey, Interop.FromUint8Array(encrypted));
    var msg = Interop.ToUint8Array(result);
    return Encoding.UTF8.GetString(msg);
  }

  public async Task<byte[]> Sign(byte[] data)
  {
    var signature = await Interop.Sign(SignatureAlgorithm, JsKey, Interop.FromUint8Array(data));
    return Interop.ToUint8Array(signature);
  }

  public async Task<bool> Verify(byte[] data, byte[] signature)
  {
    var verified = await Interop.Verify(SignatureAlgorithm, JsKey, Interop.FromUint8Array(signature),
      Interop.FromUint8Array(data));
    return verified;
  }

  private JSObject SignatureAlgorithm =>
    Engine.ToJsObject(Algorithm.With(x => x.saltLength = Algorithm.Hash().Length / 8));

  public Task<byte[]> ExportRaw() => Export("raw");
  public Task<byte[]> ExportPkcs8() => Export("pkcs8");
  public Task<byte[]> ExportSpki() => Type == KeyType.Private ? PrivateToPublic() : Export("spki");

  private async Task<byte[]> PrivateToPublic()
  {
    var publicAlgorithm = Engine.ToJsObject(Algorithm);
    var publicKey = await Interop.PrivateToPublic(JsKey, publicAlgorithm, new string[]{});
    var publicData = await Interop.ExportKey("spki", publicKey);
    var bytes = Interop.ToUint8Array(publicData);
    return bytes;
  }
  
  private async Task<byte[]> Export(string format)
  {
    var buffer = await Interop.ExportKey(format, JsKey);
    return Interop.ToUint8Array(buffer);
  }
    
  public IDerive With(IEcVerifyExportPublic otherPublicKey)
  {
    var length = (uint)((dynamic)Algorithm).Length;
    var algorithm = Engine.ToJsObject(Algorithm);
    algorithm.SetProperty("public", ((Key)otherPublicKey).JsKey);
    var hash = Algorithm.Hash();
    return new KeyDerivation(Engine, hash, async h =>
    {
      var derived = Interop.ToUint8Array(await Interop.DeriveBits(algorithm, JsKey, (int)length));
      var hashed = await h.Digest(derived);
      return hashed;
    });
  }

  public IDerive With(string info, byte[]? salt = default)
  {
    var algorithm = Engine.ToJsObject(Algorithm);
    var hash = Algorithm.Hash();
    var length = hash.Length;
    algorithm.SetProperty("info", Interop.FromUint8Array(Encoding.UTF8.GetBytes(info)));
    algorithm.SetProperty("salt", Interop.FromUint8Array(salt ?? new byte[length / 8]));
    return new KeyDerivation(Engine, hash, async h =>
      Interop.ToUint8Array(await Interop.DeriveBits(algorithm, JsKey, (int)h.Length))
      );
  }
  
  public IDerive With(uint iterations, byte[]? salt = default)
  {
    var algorithm = Engine.ToJsObject(Algorithm);
    var hash = Algorithm.Hash();
    var length = hash.Length;
    algorithm.SetProperty("iterations", iterations);
    algorithm.SetProperty("salt", Interop.FromUint8Array(salt ?? new byte[length / 8]));
    return new KeyDerivation(Engine, hash, async h =>
      Interop.ToUint8Array(await Interop.DeriveBits(algorithm, JsKey, (int)h.Length))
    );
  }
}