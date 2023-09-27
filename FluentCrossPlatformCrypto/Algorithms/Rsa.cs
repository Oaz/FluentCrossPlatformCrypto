using System.Dynamic;
using FluentCrossPlatformCrypto.Internals;

namespace FluentCrossPlatformCrypto.Algorithms;

public class Rsa<TPublic, TPrivate> : NamedHash<Rsa<TPublic, TPrivate>.Hashed>
{
  public Rsa(string name, Algorithm.Usage usage) : base(name, usage, a => new(a))
  {
  }

  public class Hashed
  {
    public readonly IKeyManagerImport<TPublic, TPrivate> Import;
    public readonly Generated Generate;

    public Hashed(ExpandoObject algorithm)
    {
      Import = new KeyManager<TPublic, TPrivate>(algorithm);
      Generate = new Generated(algorithm);
    }

    public class Generated
    {
      public IKeyManagerGenerate<IKeyPair<TPublic, TPrivate>> this[uint modulusLength] =>
        new KeyManager<TPublic, TPrivate>(_algorithm.CloneWith(x =>
        {
          x.ModulusLength = modulusLength;
          x.PublicExponent = new byte[] { 0x01, 0x00, 0x01 };
        }));

      private readonly ExpandoObject _algorithm;

      internal Generated(ExpandoObject algorithm) => _algorithm = algorithm;
    }
  }
}