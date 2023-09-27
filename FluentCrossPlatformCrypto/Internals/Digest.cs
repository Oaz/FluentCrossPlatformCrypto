using System.Text;

namespace FluentCrossPlatformCrypto.Internals;

internal class DigestParams : IDigest
{
  public DigestParams(string name, uint length)
  {
    Name = name;
    Length = length;
  }

  public string Name { get; }
  public uint Length { get; }

  public Task<byte[]> Digest(byte[] message) => IEngine.Singleton.Digest(this, message);
  public Task<byte[]> Digest(string message) => Digest(Encoding.UTF8.GetBytes(message));
}