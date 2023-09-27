using System.Dynamic;
using FluentCrossPlatformCrypto.Internals;

namespace FluentCrossPlatformCrypto.Algorithms;

public class Hkdf : NamedHash<Hkdf.Hashed>
{
  public Hkdf(string name) : base(name, Algorithm.Usage.SecretDerive, a => new(a))
  {
  }

  public class Hashed
  {
    public Hashed(ExpandoObject algorithm) => Import = new KeyManager<IDeriveHkdf>(algorithm);
    public readonly IKeyManagerImportRaw<IDeriveHkdf> Import;
  }
}