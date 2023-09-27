namespace FluentCrossPlatformCrypto.Internals.Native;

internal class KeyDerivation : Internals.Derivation
{
  private readonly Func<IDigest, Task<byte[]>> _run;

  public KeyDerivation(IDigest hash, Func<IDigest, Task<byte[]>> run)
  {
    _run = run;
    DefaultHash = hash;
  }

  protected override Task<byte[]> Derive(IDigest hash) => _run(hash);
  protected override IDigest DefaultHash { get; }
}