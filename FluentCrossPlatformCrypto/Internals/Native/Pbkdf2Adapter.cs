using System.Dynamic;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class Pbkdf2Adapter : IAdapter
{
  public IKey GenerateKey(ExpandoObject algorithm) => throw new NotSupportedException();
  public IKeyPair GenerateKeyPair(ExpandoObject algorithm) => throw new NotSupportedException();

  public IKey ImportKey(ExpandoObject algorithm, string format, byte[] data) =>
    new Pbkdf2Key(algorithm.Hash(), data);
}