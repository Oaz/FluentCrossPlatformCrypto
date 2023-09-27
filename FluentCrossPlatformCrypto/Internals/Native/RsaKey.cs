using System.Security.Cryptography;
using System.Text;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class RsaKey : IKeyPair
{
  private readonly dynamic _algorithm;

  public RsaKey(RSA rsa, HashInfo hashInfo, dynamic algorithm)
  {
    _algorithm = algorithm;
    PublicKey = new Public(rsa, hashInfo, GetSignaturePadding);
    PrivateKey = new Private(rsa, hashInfo, GetSignaturePadding);
  }

  private RSASignaturePadding? GetSignaturePadding() =>
    _algorithm.Name switch
    {
      "RSASSA-PKCS1-v1_5" => RSASignaturePadding.Pkcs1,
      "RSA-PSS" => RSASignaturePadding.Pss,
      _ => null
    };

  class Public : IEncryptExport, IVerifyExportPublic
  {
    private readonly RSA _rsa;
    private readonly HashInfo _hashInfo;
    private readonly Func<RSASignaturePadding?> _getSignaturePadding;

    public Public(RSA rsa, HashInfo hashInfo, Func<RSASignaturePadding?> getSignaturePadding)
    {
      _rsa = rsa;
      _hashInfo = hashInfo;
      _getSignaturePadding = getSignaturePadding;
    }

    public KeyType Type { get; } = KeyType.Public;

    public Task<byte[]> ExportSpki() => Task.FromResult(_rsa.ExportSubjectPublicKeyInfo());

    public Task<byte[]> Encrypt(string message) =>
      Task.FromResult(_rsa.Encrypt(Encoding.UTF8.GetBytes(message), _hashInfo.EncryptionPadding));

    public Task<bool> Verify(byte[] data, byte[] signature) =>
      Task.FromResult(_rsa.VerifyData(data, signature, _hashInfo.Name, _getSignaturePadding()!));
  }

  class Private : IDecryptExport, ISignExportPrivate
  {
    private readonly RSA _rsa;
    private readonly HashInfo _hashInfo;
    private readonly Func<RSASignaturePadding?> _getSignaturePadding;

    public Private(RSA rsa, HashInfo hashInfo, Func<RSASignaturePadding?> getRsaSignaturePadding)
    {
      _rsa = rsa;
      _hashInfo = hashInfo;
      _getSignaturePadding = getRsaSignaturePadding;
    }

    public KeyType Type { get; } = KeyType.Private;

    public Task<byte[]> ExportPkcs8() => Task.FromResult(_rsa.ExportPkcs8PrivateKey());
    public Task<byte[]> ExportSpki() => Task.FromResult(_rsa.ExportSubjectPublicKeyInfo());

    public Task<string> Decrypt(byte[] data) =>
      Task.FromResult(Encoding.UTF8.GetString(_rsa.Decrypt(data, _hashInfo.EncryptionPadding)));

    public Task<byte[]> Sign(byte[] data) =>
      Task.FromResult(_rsa.SignData(data, _hashInfo.Name, _getSignaturePadding()!));

  }
  
  public IKey? PublicKey { get; }
  public IKey? PrivateKey { get; }
}