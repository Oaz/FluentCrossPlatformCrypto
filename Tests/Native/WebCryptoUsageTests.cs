using FluentCrossPlatformCrypto.Internals.Browser;

namespace FluentCrossPlatformCrypto.Tests.Native;

public class WebCryptoUsageTests
{

  [TestCaseSource(nameof(Cases))]
  public void GetUsages(KeyType keyType, Algorithm.Usage usage, string expectedUsages)
  {
    var actualUsages = WebCryptoUsage.Get(usage, keyType);
    Assert.That(string.Join(',',actualUsages), Is.EqualTo(expectedUsages));
  }
  
  public static object[] Cases =
  {
    new object[] { KeyType.Secret, Algorithm.Usage.SecretEncrypt, "encrypt" },
    new object[] { KeyType.Secret, Algorithm.Usage.SecretDecrypt, "decrypt" },
    new object[] { KeyType.Secret, Algorithm.Usage.SecretSign, "sign" },
    new object[] { KeyType.Secret, Algorithm.Usage.SecretVerify, "verify" },
    new object[] { KeyType.Secret, Algorithm.Usage.SecretDerive, "deriveBits,deriveKey" },
    
    new object[] { KeyType.Public, Algorithm.Usage.PublicEncrypt, "encrypt" },
    new object[] { KeyType.Public, Algorithm.Usage.PublicVerify, "verify" },

    new object[] { KeyType.Private, Algorithm.Usage.PrivateDecrypt, "decrypt" },
    new object[] { KeyType.Private, Algorithm.Usage.PrivateSign, "sign" },
    new object[] { KeyType.Private, Algorithm.Usage.PrivateDerive, "deriveBits,deriveKey" },
    
    new object[] { KeyType.Private|KeyType.Public, Algorithm.Usage.PublicEncrypt, "encrypt" },
    new object[] { KeyType.Private|KeyType.Public, Algorithm.Usage.PublicVerify, "verify" },
    new object[] { KeyType.Private|KeyType.Public, Algorithm.Usage.PrivateDecrypt, "decrypt" },
    new object[] { KeyType.Private|KeyType.Public, Algorithm.Usage.PrivateSign, "sign" },
    new object[] { KeyType.Private|KeyType.Public, Algorithm.Usage.PrivateDerive, "deriveBits,deriveKey" },
  };

}