namespace FluentCrossPlatformCrypto.Internals;

internal abstract class Derivation : IDerive
{
  protected abstract Task<byte[]> Derive(IDigest hash);
  protected abstract IDigest DefaultHash { get; }
  
  public Task<byte[]> Derive() => Derive(DefaultHash);

  public async Task<IEncryptDecrypt> DeriveToAes() =>
    await Algorithm.Aes.Cbc.Import.Raw(await Derive(Algorithm.Digest.Sha256));

  public async Task<ISignVerify> DeriveToHmac() =>
    await Algorithm.Hmac[DefaultHash].Import.Raw(await Derive(DefaultHash));
}