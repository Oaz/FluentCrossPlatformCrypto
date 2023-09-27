using System.Dynamic;
using System.Runtime.Versioning;

namespace FluentCrossPlatformCrypto.Internals.Browser;

[SupportedOSPlatform("browser")]
internal class SelfSufficientEncryption : IEncryption
{
  public ExpandoObject BeforeEncrypt(Key k) => k.Algorithm;

  public byte[] AfterEncrypt(ExpandoObject algo, byte[] encrypted) => encrypted;

  public (ExpandoObject algo, byte[] encrypted) BeforeDecrypt(Key k, byte[] data) => (k.Algorithm, data);
}


