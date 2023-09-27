using System.Security.Cryptography;
using System.Text;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class HkdfKey : IKey, IDeriveHkdf
{
  private readonly IDigest _hash;
  private readonly byte[] _ikm;

  public HkdfKey(IDigest hash, byte[] ikm)
  {
    _hash = hash;
    _ikm = ikm;
  }

  public Task<byte[]> ExportRaw() => Task.FromResult(_ikm);

  public IDerive With(string info, byte[]? salt = default) =>
    new KeyDerivation(_hash, h =>
    {
      var output = new byte[h.Length / 8];
      HKDF.DeriveKey(HashInfo.Get(h).Name, _ikm, output, salt ?? new byte[_hash.Length / 8], Encoding.UTF8.GetBytes(info));
      return Task.FromResult(output);
    });

  public KeyType Type { get; } = KeyType.Secret;
  
}