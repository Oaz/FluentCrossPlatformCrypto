using System.Dynamic;
using System.Security.Cryptography;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class AesCbcAdapter : IAdapter
{
  public IKey GenerateKey(ExpandoObject algorithm)
  {
    var aes = Aes.Create();
    aes.KeySize = (int)algorithm.D().Length;
    aes.Mode = CipherMode.CBC;
    aes.GenerateKey();
    return new AesKey(aes);
  }

  public IKeyPair GenerateKeyPair(ExpandoObject algorithm) => throw new NotSupportedException();

  public IKey ImportKey(ExpandoObject algorithm, string format, byte[] data)
  {
    var aes = Aes.Create();
    aes.Mode = CipherMode.CBC;
    aes.Key = data;
    return new AesKey(aes);
  }
}