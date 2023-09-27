namespace FluentCrossPlatformCrypto;

public static class Helpers
{
  public static string ToBase64(this byte[] self) => Convert.ToBase64String(self);
  public static byte[] FromBase64(this string self) => Convert.FromBase64String(self);
}