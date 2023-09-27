using System.Runtime.Versioning;
using FluentCrossPlatformCrypto.Tests.Browser.TestFramework;

namespace FluentCrossPlatformCrypto.Tests.Browser;

[SupportedOSPlatform("browser")]
internal static class Program
{
  public static async Task Main(string[] args)
  {
    var suite = new Suite();

    new AlgorithmTests().Add(suite);
    new DigestTests().Add(suite);
    new ExportImportTests().Add(suite);
    new EncryptDecryptTests().Add(suite);
    new SignVerifyTests().Add(suite);
    new KeyDerivationTests().Add(suite);

    await suite.Run();
  }
}