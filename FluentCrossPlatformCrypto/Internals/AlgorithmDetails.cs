using System.Dynamic;

namespace FluentCrossPlatformCrypto.Internals;

internal static class AlgorithmDetails
{
  public static ExpandoObject Is(string name, Algorithm.Usage usage)
  {
    dynamic x = new ExpandoObject();
    x.Name = name;
    x.Usage = usage;
    return x;
  }

  public static dynamic D(this ExpandoObject @this) => @this;

  public static string Name(this ExpandoObject @this) => ((dynamic)@this).Name;
  public static Algorithm.Usage Usage(this ExpandoObject @this) => ((dynamic)@this).Usage;
  public static IDigest Hash(this ExpandoObject @this) => ((dynamic)@this).Hash;

  public static ExpandoObject And(this ExpandoObject @this, string key, object value)
  {
    (@this as IDictionary<string,object?>).Add(key, value);
    return @this;
  }

  public static bool HasProperty(this ExpandoObject @this, string propertyName) =>
    ((IDictionary<string, object?>)@this).ContainsKey(propertyName);
  
  public static ExpandoObject CloneWith(this ExpandoObject @this, Action<dynamic> action)
    => @this.Clone().With(action);

  public static ExpandoObject With(this ExpandoObject @this, Action<dynamic> action)
  {
    action(@this);
    return @this;
  }
  
  public static ExpandoObject Clone(this ExpandoObject @this)
  {
    var clone = new ExpandoObject();
    var cloned = clone as IDictionary<string, object>;
    foreach (var kvp in @this as IDictionary<string, object>)
      cloned.Add(kvp.Key, kvp.Value is ExpandoObject expandoObject ? expandoObject.Clone() : kvp.Value);
    return clone;
  }
}