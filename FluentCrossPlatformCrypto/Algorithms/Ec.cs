using System.Dynamic;
using FluentCrossPlatformCrypto.Internals;

namespace FluentCrossPlatformCrypto.Algorithms;

public class Ec
{
  public readonly Curved P256 = new("P-256",256);
  public readonly Curved P384 = new("P-384",384);
  public readonly Curved P521 = new("P-521",528);
  
  public class Curved
  {
    public Curved(string curve, int length)
    {
      Dsa = new("ECDSA", Algorithm.Usage.PrivateSign|Algorithm.Usage.PublicVerify, curve, length);
      Dh = new("ECDH", Algorithm.Usage.PrivateDerive|Algorithm.Usage.PublicDerive, curve, length);
    }

    public readonly Intent<ISignExportPrivate> Dsa;
    public readonly Intent<IEcDeriveExportPrivate> Dh;
  }

  public class Intent<TPrivate>
  {
    private readonly ExpandoObject _algorithm;
    public Handler<TPrivate> this[IDigest hash] => new (_algorithm,hash);

    public Intent(string name, Algorithm.Usage usage, string curve, int length)
    {
      _algorithm = AlgorithmDetails.Is(name, usage).With(x =>
      {
        x.NamedCurve = curve;
        x.Length = length;
      });
    }
  }

  public class Handler<TPrivate>
  {
    public Handler(ExpandoObject algorithm, IDigest hash)
    {
      var algorithmWithHash = algorithm.Clone().With(x =>
      {
        x.Hash = hash;
      });
      var manager = new KeyManager<IEcVerifyExportPublic, TPrivate>(algorithmWithHash);
      Import = manager;
      Generate = manager;
    }
    public readonly IKeyManagerImport<IEcVerifyExportPublic, TPrivate> Import;
    public readonly IKeyManagerGenerate<IKeyPair<IEcVerifyExportPublic, TPrivate>> Generate;
    
  }
}