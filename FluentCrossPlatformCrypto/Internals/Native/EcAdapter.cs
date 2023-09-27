using System.Dynamic;
using System.Security.Cryptography;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class EcAdapter : IAdapter
{
  public IKey GenerateKey(ExpandoObject algorithm) => throw new NotSupportedException();

  IKeyPair IAdapter.GenerateKeyPair(ExpandoObject algorithm)
  {
    var ec = ECDsa.Create(GetCurve(algorithm));
    return new EcKey(ec,algorithm);
  }

  public IKey ImportKey(ExpandoObject algorithm, string format, byte[] data)
  {
    var ec = ECDsa.Create(GetCurve(algorithm));
    if (format == "spki")
    {
      ec.ImportSubjectPublicKeyInfo(data, out var _);
      return new EcKey(ec,algorithm).PublicKey!;
    }
    ec.ImportPkcs8PrivateKey(data, out var _);
    return new EcKey(ec,algorithm).PrivateKey!;
  }
  
  private ECCurve GetCurve(dynamic algorithm) => _curves[algorithm.NamedCurve];

  private readonly Dictionary<string, ECCurve> _curves = new()
  {
    { "P-256", ECCurve.NamedCurves.nistP256 },
    { "P-384", ECCurve.NamedCurves.nistP384 },
    { "P-521", ECCurve.NamedCurves.nistP521 },
  };
}