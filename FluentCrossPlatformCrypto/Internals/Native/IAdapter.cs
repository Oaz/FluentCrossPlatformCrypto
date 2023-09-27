using System.Dynamic;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal interface IAdapter
{
  IKey GenerateKey(ExpandoObject algorithm);
  IKeyPair GenerateKeyPair(ExpandoObject algorithm);
  IKey ImportKey(ExpandoObject algorithm, string format, byte[] data);
}