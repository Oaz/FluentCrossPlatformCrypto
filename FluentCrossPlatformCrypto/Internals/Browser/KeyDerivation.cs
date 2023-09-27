using System.Runtime.Versioning;

namespace FluentCrossPlatformCrypto.Internals.Browser;

[SupportedOSPlatform("browser")]
internal class KeyDerivation : Internals.Derivation
{
  private readonly BrowserEngine _engine;
  private readonly Func<IDigest, Task<byte[]>> _run;

  public KeyDerivation(BrowserEngine engine, IDigest digest, Func<IDigest, Task<byte[]>> run)
  {
    _engine = engine;
    _run = run;
    DefaultHash = digest;
  }

  protected override Task<byte[]> Derive(IDigest hash) => _run(hash);
  protected override IDigest DefaultHash { get; }
}