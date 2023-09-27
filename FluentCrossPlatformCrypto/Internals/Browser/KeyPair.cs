using System.Dynamic;
using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;

namespace FluentCrossPlatformCrypto.Internals.Browser;

[SupportedOSPlatform("browser")]
internal class KeyPair: IKeyPair
{
  private readonly JSObject _jsKey;

  public KeyPair(JSObject jsKey, ExpandoObject algorithm, BrowserEngine engine)
  {
    _jsKey = jsKey;
    PublicKey = GetProperty<IKey>("publicKey", o => new Key(o, KeyType.Public, algorithm, engine));
    PrivateKey = GetProperty<IKey>("privateKey", o => new Key(o, KeyType.Private, algorithm, engine));
  }
  public IKey? PublicKey { get; }
  public IKey? PrivateKey { get; }
  
  private JSObject? GetProperty(string name) => _jsKey.HasProperty(name) ? _jsKey.GetPropertyAsJSObject(name) : null;

  private T? GetProperty<T>(string name, Func<JSObject, T> make)
  {
    var jso = GetProperty(name);
    return jso == null ? default : make(jso);
  }

}