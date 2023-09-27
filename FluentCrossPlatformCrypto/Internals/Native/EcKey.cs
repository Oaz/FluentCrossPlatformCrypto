using System.Dynamic;
using System.Security.Cryptography;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class EcKey : IKeyPair
{
  public EcKey(ECAlgorithm ec, ExpandoObject algorithm)
  {
    PublicKey = new Public(ec,algorithm);
    PrivateKey = new Private(ec,algorithm);
  }
  
  public IKey? PublicKey { get; }
  public IKey? PrivateKey { get; }

  class Public : IEcVerifyExportPublic
  {
    private readonly ECAlgorithm _ec;
    private readonly HashAlgorithmName _hashName;

    public Public(ECAlgorithm ec, ExpandoObject algorithm)
    {
      _ec = ec;
      _hashName = HashInfo.Get(algorithm.Hash()).Name;
    }

    public KeyType Type { get; } = KeyType.Public;
    
    public Task<bool> Verify(byte[] data, byte[] signature) => Task.FromResult(((ECDsa)_ec).VerifyData(data, signature, _hashName));
    public Task<byte[]> ExportSpki() => Task.FromResult(_ec.ExportSubjectPublicKeyInfo());
  }

  class Private : ISignExportPrivate, IEcDeriveExportPrivate
  {
    private readonly ECAlgorithm _ec;
    private readonly HashAlgorithmName _hashName;
    private readonly IDigest _hash;

    public Private(ECAlgorithm ec, ExpandoObject algorithm)
    {
      _ec = ec;
      _hash = algorithm.Hash();
      _hashName = HashInfo.Get(algorithm.Hash()).Name;
    }

    public KeyType Type { get; } = KeyType.Private;
    
    public Task<byte[]> Sign(byte[] data) => Task.FromResult(((ECDsa)_ec).SignData(data, _hashName));
    public Task<byte[]> ExportPkcs8() => Task.FromResult(_ec.ExportPkcs8PrivateKey());
    public Task<byte[]> ExportSpki() => Task.FromResult(_ec.ExportSubjectPublicKeyInfo());
    
    public IDerive With(IEcVerifyExportPublic otherPublicKey) => new KeyDerivation(_hash, async h =>
    {
      var dh = ECDiffieHellman.Create();
      dh.ImportPkcs8PrivateKey(_ec.ExportPkcs8PrivateKey(), out var _);
      var spki = await otherPublicKey.ExportSpki();
      var otherPublic = ECDiffieHellman.Create();
      otherPublic.ImportSubjectPublicKeyInfo(spki, out var _);
      var bytes = dh.DeriveKeyFromHash(otherPublic.PublicKey, HashInfo.Get(h).Name);
      return bytes;
    });
  }
}