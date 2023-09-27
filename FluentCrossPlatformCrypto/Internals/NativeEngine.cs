using System.Dynamic;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using FluentCrossPlatformCrypto.Internals.Native;

namespace FluentCrossPlatformCrypto.Internals;

[UnsupportedOSPlatform("browser")]
internal class NativeEngine : IEngine
{
  public static IEngine Create() => new NativeEngine();

  private NativeEngine() => _adapters = CreateAdapters();
  private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

  public byte[] GetRandomValues(uint length)
  {
    var data = new byte[length];
    _rng.GetBytes(data);
    return data;
  }

  private readonly Dictionary<string, IAdapter> _adapters;

  private Dictionary<string, IAdapter> CreateAdapters() => new ()
  {
    {"AES-CBC",new AesCbcAdapter()},
    {"HMAC",new HmacAdapter()},
    {"HKDF", new HkdfAdapter()},
    {"PBKDF2", new Pbkdf2Adapter()},
    {"RSA-OAEP", new RsaAdapter()},
    {"RSA-PSS", new RsaAdapter()},
    {"RSASSA-PKCS1-v1_5", new RsaAdapter()},
    {"ECDSA", new EcAdapter()},
    {"ECDH", new EcAdapter()},
  };
  
  private IAdapter GetAdapter(ExpandoObject algorithmDetails)
  {
    if (_adapters.TryGetValue(algorithmDetails.Name(), out var adapter))
      return adapter;
    throw new NotSupportedException($"Algorithm {algorithmDetails.Name()} is not supported in native implementation");
  }

  Task<IKey> IEngine.ImportKey(string format, ExpandoObject algorithm, byte[] data) =>
    Task.FromResult(GetAdapter(algorithm).ImportKey(algorithm, format, data));

  Task<IKey> IEngine.GenerateKey(ExpandoObject algorithm) =>
    Task.FromResult(GetAdapter(algorithm).GenerateKey(algorithm));

  Task<IKeyPair> IEngine.GenerateKeyPair(ExpandoObject algorithm) =>
    Task.FromResult(GetAdapter(algorithm).GenerateKeyPair(algorithm));


  public Task<byte[]> Digest(IDigest algorithm, byte[] message)
  {
    if (!_hashs.TryGetValue(algorithm.Name, out var hashAlgorithm))
      throw new NotSupportedException($"Algorithm {algorithm.Name} is not supported");
    return Task.FromResult(hashAlgorithm.ComputeHash(message));
  }

  private readonly Dictionary<string, HashAlgorithm> _hashs = new ()
  {
    {"SHA-1", SHA1.Create()},
    {"SHA-256", SHA256.Create()},
    {"SHA-384", SHA384.Create()},
    {"SHA-512", SHA512.Create()},
  };
}