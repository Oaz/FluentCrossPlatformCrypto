using FluentCrossPlatformCrypto.Internals;

namespace FluentCrossPlatformCrypto;

public static class Algorithm
{
  public static class Digest
  {
    public static readonly IDigest Sha1 = new DigestParams("SHA-1", 160);
    public static readonly IDigest Sha256 = new DigestParams("SHA-256", 256);
    public static readonly IDigest Sha384 = new DigestParams("SHA-384", 384);
    public static readonly IDigest Sha512 = new DigestParams("SHA-512", 512);
  }
  
  public static class Aes
  {
    public static readonly Algorithms.Aes Cbc = new("AES-CBC");
    public static readonly Algorithms.Aes Ctr = new("AES-CTR");
    public static readonly Algorithms.Aes Gcm = new("AES-GCM");
  }
  
  public static readonly Algorithms.Hmac Hmac = new("HMAC", Usage.SecretSign|Usage.SecretVerify);
  
  public static class Rsa
  {
    public static readonly Algorithms.Rsa<IEncryptExport, IDecryptExport> Oaep = new("RSA-OAEP", Usage.PublicEncrypt|Usage.PrivateDecrypt);
    public static readonly Algorithms.Rsa<IVerifyExportPublic, ISignExportPrivate> SsaPkcs1V15 = new("RSASSA-PKCS1-v1_5", Usage.PublicVerify|Usage.PrivateSign);
    public static readonly Algorithms.Rsa<IVerifyExportPublic, ISignExportPrivate> Pss = new("RSA-PSS", Usage.PublicVerify|Usage.PrivateSign);
  }
  
  public static readonly Algorithms.Ec Ec = new();
  
  public static readonly Algorithms.Pbkdf2 Pbkdf2 = new("PBKDF2");
  public static readonly Algorithms.Hkdf Hkdf = new("HKDF");

  [Flags]
  public enum Usage
  {
    SecretEncrypt = 1,
    PublicEncrypt = 2,
    SecretDecrypt = 4,
    PrivateDecrypt = 8,
    SecretVerify = 16,
    PublicVerify = 32,
    SecretSign = 64,
    PrivateSign = 128,
    SecretDerive = 256,
    PrivateDerive = 512,
    PublicDerive = 1024,
  }
}