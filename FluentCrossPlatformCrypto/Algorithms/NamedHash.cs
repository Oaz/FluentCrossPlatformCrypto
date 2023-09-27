using System.Dynamic;
using FluentCrossPlatformCrypto.Internals;

namespace FluentCrossPlatformCrypto.Algorithms;

public class NamedHash<T>
{
  private readonly string _name;
  private readonly Algorithm.Usage _usage;
  private readonly Func<ExpandoObject, T> _factory;

  public NamedHash(string name, Algorithm.Usage usage, Func<ExpandoObject, T> factory)
  {
    _name = name;
    _usage = usage;
    _factory = factory;
  }

  public T this[IDigest hash] => _factory(AlgorithmDetails.Is(_name,_usage).With(x =>
  {
    x.Hash = hash;
  }));
}

