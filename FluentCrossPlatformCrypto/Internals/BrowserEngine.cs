using System.Dynamic;
using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using FluentCrossPlatformCrypto.Internals.Browser;

namespace FluentCrossPlatformCrypto.Internals;

[SupportedOSPlatform("browser")]
internal class BrowserEngine : IEngine
{
  public static IEngine Create() => new BrowserEngine();

  public byte[] GetRandomValues(uint length) =>
    Interop.ToUint8Array(Interop.GetRandomValues(Interop.CreateUint8Array((int)length)));

  internal IEncryption GetEncryption(Key key)
  {
    var name = key.Algorithm.Name();
    if (_encryptions.TryGetValue(name, out var encryption))
      return encryption;
    throw new NotSupportedException($"Algorithm {name} does not support encryption in browser implementation");
  }

  private Dictionary<string, IEncryption> _encryptions = new()
  {
    { "AES-CBC", new AesCbcEncryption() },
    { "RSA-OAEP", new SelfSufficientEncryption() },
  };
  
  async Task<IKey> IEngine.ImportKey(string format, ExpandoObject algorithm, byte[] data)
  {
    var keyType = format switch
      {
        "raw" => KeyType.Secret,
        "pkcs8" => KeyType.Private,
        "spki" => KeyType.Public,
        _ => throw new NotSupportedException($"Unsupported {format} format")
      };
    var usages = WebCryptoUsage.Get(algorithm.Usage(), keyType);
    var buffer = Interop.FromUint8Array(data);
    var keyJso = await Interop.ImportKey(format, buffer, ToJsObject(algorithm), IsExtractable(algorithm), usages);
    return new Key(keyJso, keyType, algorithm, this);
  }
  
  async Task<IKey> IEngine.GenerateKey(ExpandoObject algorithm)
  {
    var keyJso = await Interop.GenerateKey(
      ToJsObject(algorithm), IsExtractable(algorithm),
      WebCryptoUsage.Get(algorithm.Usage(),KeyType.Secret)
      );
    return new Key(keyJso, KeyType.Secret, algorithm, this);
  }

  async Task<IKeyPair> IEngine.GenerateKeyPair(ExpandoObject algorithm)
  {
    var keyJso = await Interop.GenerateKey(
      ToJsObject(algorithm),IsExtractable(algorithm),
      WebCryptoUsage.Get(algorithm.Usage(),KeyType.Private|KeyType.Public)
      );
    return new KeyPair(keyJso, algorithm, this);
  }

  private static bool IsExtractable(ExpandoObject algorithm) => !(algorithm.Name() is "HKDF" or "PBKDF2");

  public async Task<byte[]> Digest(IDigest algorithm, byte[] message) =>
    Interop.ToUint8Array(await Interop.Digest(algorithm.Name, Interop.FromUint8Array(message)));

  internal JSObject ToJsObject(ExpandoObject details) => Interop.Eval(ToJsSource(details));

  private string ToJsSource(object? obj)
  {
    if (obj == null || obj is Algorithm.Usage)
      return "undefined";
    if (obj is string s)
      return $"\"{s}\"";
    if (obj is byte[] bs)
      return $"new Uint8Array({ToJsSource(bs.Select(x => (uint)x).ToArray())})";
    if (obj is Array a)
      return $"[{string.Join(',', a.Cast<object>().Select(ToJsSource))}]";
    if (obj is DigestParams dp)
      return $"\"{dp.Name}\"";
    if (obj is ExpandoObject)
    {
      var dict = obj as IDictionary<string, object?>;
      var values = string.Join(',', dict!.Select(kv => $"{Char.ToLower(kv.Key[0])}{kv.Key[1..]}:{ToJsSource(kv.Value)}"));
      // Console.WriteLine($"values = {values}");
      return $"Object.create({{{values}}})";
    }
    return obj.ToString()!;
  }
}