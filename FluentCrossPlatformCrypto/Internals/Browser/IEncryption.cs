using System.Dynamic;

namespace FluentCrossPlatformCrypto.Internals.Browser;

internal interface IEncryption
{
  ExpandoObject BeforeEncrypt(Key k);
  byte[] AfterEncrypt(ExpandoObject algo, byte[] encrypted);
  (ExpandoObject algo, byte[] encrypted) BeforeDecrypt(Key k, byte[] data);
}