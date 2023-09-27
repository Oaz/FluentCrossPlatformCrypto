using FluentCrossPlatformCrypto.Internals;

namespace FluentCrossPlatformCrypto.Algorithms;

public class Aes
{
  public Aes(string name)
  {
    Import = new KeyManager<IEncryptDecrypt>(
      AlgorithmDetails.Is(name, Algorithm.Usage.SecretEncrypt | Algorithm.Usage.SecretDecrypt)
    );
    Length128 = new WithLength(name, 128);
    Length192 = new WithLength(name, 192);
    Length256 = new WithLength(name, 256);
  }

  public readonly IKeyManagerImportRaw<IEncryptDecrypt> Import;
  public readonly WithLength Length128;
  public readonly WithLength Length192;
  public readonly WithLength Length256;

  public class WithLength
  {
    public WithLength(string name, int length) =>
      Generate = new KeyManager<IEncryptDecrypt>(
        AlgorithmDetails.Is(name, Algorithm.Usage.SecretEncrypt | Algorithm.Usage.SecretDecrypt)
          .With(x => { x.Length = length; }));

    public readonly IKeyManagerGenerate<IEncryptDecrypt> Generate;
  }
}