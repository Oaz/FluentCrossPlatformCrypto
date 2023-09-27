using System.Dynamic;
using System.Text;

namespace FluentCrossPlatformCrypto.Internals;

internal class KeyManager<T> : IKeyManagerGenerate<T>, IKeyManagerImportRaw<T>, IKeyManagerImportText<T>
{
  private readonly ExpandoObject _details;

  public KeyManager(ExpandoObject details)
  {
    _details = details;
  }

  public async Task<T> Key()
  {
    return (T)await IEngine.Singleton.GenerateKey(_details);
  }

  public async Task<T> Raw(byte[] data)
  {
    return (T)await IEngine.Singleton.ImportKey("raw",_details, data);
  }

  public Task<T> Text(string data) => Raw(Encoding.UTF8.GetBytes(data));
}

internal class KeyManager<TPublic,TPrivate> : IKeyManagerGenerate<IKeyPair<TPublic,TPrivate>>, IKeyManagerImport<TPublic,TPrivate>
{
  private readonly ExpandoObject _details;

  public KeyManager(ExpandoObject details)
  {
    _details = details;
  }

  class KeyPair : IKeyPair<TPublic,TPrivate>
  {
    private readonly IKeyPair _pair;
    private readonly IEngine _engine;

    public KeyPair(TPublic publicKey, TPrivate privateKey, IKeyPair pair, IEngine engine)
    {
      _pair = pair;
      _engine = engine;
      PublicKey = publicKey;
      PrivateKey = privateKey;
    }

    public TPublic PublicKey { get; }
    public TPrivate PrivateKey { get; }
  }

  public async Task<IKeyPair<TPublic,TPrivate>> Key()
  {
    var kEngine = IEngine.Singleton;
    var key = await kEngine.GenerateKeyPair(_details);
    return new KeyPair((TPublic) key.PublicKey!, (TPrivate) key.PrivateKey!, key, kEngine);
  }

  public async Task<TPrivate> Pkcs8(byte[] data)
  {
    return (TPrivate)await IEngine.Singleton.ImportKey("pkcs8",_details, data);
  }

  public async Task<TPublic> Spki(byte[] data)
  {
    return (TPublic)await IEngine.Singleton.ImportKey("spki",_details, data);
  }
}

internal static class UsageHelper
{
  public static ISet<Type> Interfaces<T>() => typeof(T).GetInterfaces().ToHashSet();
}
