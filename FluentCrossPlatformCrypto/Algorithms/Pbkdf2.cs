using System.Dynamic;
using FluentCrossPlatformCrypto.Internals;

namespace FluentCrossPlatformCrypto.Algorithms;

public class Pbkdf2 : NamedHash<Pbkdf2.Hashed>
{
  public Pbkdf2(string name) : base(name, Algorithm.Usage.SecretDerive, a => new(a))
  {
  }

  public class Hashed
  {
    public Hashed(ExpandoObject algorithm) => Import = new KeyManager<IDerivePbkdf2>(algorithm);
    public readonly IKeyManagerImportText<IDerivePbkdf2> Import;
  }
}