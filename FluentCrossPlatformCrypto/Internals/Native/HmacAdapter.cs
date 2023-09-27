using System.Dynamic;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class HmacAdapter : IAdapter
{
  public IKey GenerateKey(ExpandoObject algorithm)
  {
    var details = HashInfo.Get(algorithm.Hash());
    var keyData = IEngine.Singleton.GetRandomValues(details.HmacLength);
    return new HmacKey(details.HmacCreate(keyData));
  }

  IKeyPair IAdapter.GenerateKeyPair(ExpandoObject algorithm) => throw new NotSupportedException();

  public IKey ImportKey(ExpandoObject algorithm, string format, byte[] data) =>
    new HmacKey(HashInfo.Get(algorithm.Hash()).HmacCreate(data));

}