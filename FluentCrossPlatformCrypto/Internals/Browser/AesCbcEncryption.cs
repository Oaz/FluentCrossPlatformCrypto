using System.Dynamic;
using System.Runtime.Versioning;

namespace FluentCrossPlatformCrypto.Internals.Browser;

[SupportedOSPlatform("browser")]
internal class AesCbcEncryption : IEncryption
{
  public ExpandoObject BeforeEncrypt(Key k) => k.Algorithm.With(x => x.iv = GetRandomVector(16));
  
  private static byte[] GetRandomVector(uint length) =>
    Interop.ToUint8Array(Interop.GetRandomValues(Interop.CreateUint8Array((int)length)));

  public byte[] AfterEncrypt(ExpandoObject algo, byte[] encrypted) =>
    ((byte[])algo.D().iv).Concat(encrypted).ToArray();

  public (ExpandoObject algo, byte[] encrypted) BeforeDecrypt(Key k, byte[] data)
  {
    var iv = data.Take(16).ToArray();
    var algo = k.Algorithm.With(x => x.iv = iv);
    var encrypted = data.Skip(16).ToArray();
    return (algo, encrypted);
  }
}

