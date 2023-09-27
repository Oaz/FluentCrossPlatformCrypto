using System.Dynamic;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class HkdfAdapter : IAdapter
{

  public IKey GenerateKey(ExpandoObject algorithm) => throw new NotSupportedException();
  public IKeyPair GenerateKeyPair(ExpandoObject algorithm) => throw new NotSupportedException();

  public IKey ImportKey(ExpandoObject algorithm, string format, byte[] data) =>
    new HkdfKey(algorithm.Hash(), data);
}