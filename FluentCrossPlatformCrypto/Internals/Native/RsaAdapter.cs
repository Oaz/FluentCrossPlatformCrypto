using System.Dynamic;
using System.Security.Cryptography;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class RsaAdapter : IAdapter
{
  public IKey GenerateKey(ExpandoObject algorithm) => throw new NotSupportedException();

  public IKeyPair GenerateKeyPair(ExpandoObject algorithm)
  {
    var rsa = RSA.Create((int)algorithm.D().ModulusLength);
    return new RsaKey(rsa, GetHashInfo(algorithm), algorithm);
  }

  public IKey ImportKey(ExpandoObject algorithm, string format, byte[] data)
  {
    var rsa = RSA.Create();
    if (format == "spki")
    {
      rsa.ImportSubjectPublicKeyInfo(data, out var _);
      return new RsaKey(rsa, GetHashInfo(algorithm), algorithm).PublicKey!;
    }
    rsa.ImportPkcs8PrivateKey(data, out var _);
    return new RsaKey(rsa, GetHashInfo(algorithm), algorithm).PrivateKey!;
  }

  private HashInfo GetHashInfo(ExpandoObject algorithm) => HashInfo.Get(algorithm.Hash());

}