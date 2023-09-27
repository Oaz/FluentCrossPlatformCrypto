namespace FluentCrossPlatformCrypto.Internals.Browser;

public static class WebCryptoUsage
{
  public static string[] Get(Algorithm.Usage usages, KeyType keyType)
  {
    var result = Find(usages, keyType).Distinct().ToArray();
    // Console.WriteLine($"Usages={string.Join(',', result)}");
    return result;
  }

  private static IEnumerable<string> Find(Algorithm.Usage usages, KeyType keyType)
  {
    if (keyType == KeyType.Secret)
    {
      if (usages.HasFlag(Algorithm.Usage.SecretEncrypt))
        yield return "encrypt";
      if (usages.HasFlag(Algorithm.Usage.SecretDecrypt))
        yield return "decrypt";
      if (usages.HasFlag(Algorithm.Usage.SecretSign))
        yield return "sign";
      if (usages.HasFlag(Algorithm.Usage.SecretVerify))
        yield return "verify";
      if (usages.HasFlag(Algorithm.Usage.SecretDerive))
      {
        yield return "deriveBits";
        yield return "deriveKey";
      }
    }
    if ((keyType & KeyType.Private) != 0)
    {
      if (usages.HasFlag(Algorithm.Usage.PrivateDecrypt))
        yield return "decrypt";
      if (usages.HasFlag(Algorithm.Usage.PrivateSign))
        yield return "sign";
      if (usages.HasFlag(Algorithm.Usage.PrivateDerive))
      {
        yield return "deriveBits";
        yield return "deriveKey";
      }
    }
    if ((keyType & KeyType.Public) != 0)
    {
      if (usages.HasFlag(Algorithm.Usage.PublicEncrypt))
        yield return "encrypt";
      if (usages.HasFlag(Algorithm.Usage.PublicVerify))
        yield return "verify";
    }
  }
}