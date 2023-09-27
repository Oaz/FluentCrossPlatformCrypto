using System.Dynamic;
using FluentCrossPlatformCrypto.Internals;

namespace FluentCrossPlatformCrypto.Algorithms;

public class Hmac : NamedHash<Hmac.Hashed>
{
  public Hmac(string name, Algorithm.Usage usage) : base(name, usage, a => new(a))
  {
  }

  public class Hashed
  {
    public readonly IKeyManagerImportRaw<ISignVerify> Import;
    public readonly IKeyManagerGenerate<ISignVerify> Generate;

    public Hashed(ExpandoObject algorithm)
    {
      var manager = new KeyManager<ISignVerify>(algorithm);
      Import = manager;
      Generate = manager;
    }
  }

}