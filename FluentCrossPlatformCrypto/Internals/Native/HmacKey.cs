using System.Security.Cryptography;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class HmacKey : ISignVerify
{
  private readonly HMAC _hmac;

  public HmacKey(HMAC hmac)
  {
    _hmac = hmac;
  }

  public KeyType Type { get; } = KeyType.Secret;
  
  public Task<bool> Verify(byte[] data, byte[] signature)
  {
    var actualSignature = _hmac.ComputeHash(data);
    return Task.FromResult(actualSignature.SequenceEqual(signature));
  }

  public Task<byte[]> Sign(byte[] data) => Task.FromResult(_hmac.ComputeHash(data));

  public Task<byte[]> ExportRaw() => Task.FromResult(_hmac.Key);
}