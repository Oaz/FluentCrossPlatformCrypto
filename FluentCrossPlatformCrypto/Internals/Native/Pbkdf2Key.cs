using System.Security.Cryptography;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class Pbkdf2Key : IKey, IDerivePbkdf2
{
  private readonly IDigest _hash;
  private readonly byte[] _ikm;

  public Pbkdf2Key(IDigest hash, byte[] ikm)
  {
    _hash = hash;
    _ikm = ikm;
  }

  public Task<byte[]> ExportRaw() => Task.FromResult(_ikm);
  public IDerive With(uint iterations, byte[]? salt = default) =>
    new KeyDerivation(_hash, h =>
      Task.FromResult(Rfc2898DeriveBytes.Pbkdf2(
        _ikm, salt ?? new byte[_hash.Length / 8], (int)iterations,
        HashInfo.Get(h).Name, (int)h.Length / 8
        ))
      );

  public KeyType Type { get; } = KeyType.Secret;
  
}