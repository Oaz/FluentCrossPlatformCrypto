using FluentCrossPlatformCrypto.Tests.Browser.TestFramework;
using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Browser;

public class EncryptDecryptTests : Helpers.EncryptDecryptTests
{
  public void Add(Suite suite)
  {
    Assert = new Assert();

    TestEncryptDecrypt( "AES-CBC 128", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc128, 80 );
    TestEncryptDecrypt( "AES-CBC 256", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc256, 80 );
  
    void TestEncryptDecrypt<T>(string description, IKeyManagerImportRaw<T> importAlgo, string keyData,
      int expectedEncrypted) where T : IEncryptDecrypt =>
      suite.Test($"Encrypt Decrypt {description}", () => SymEncryptDecrypt(importAlgo, keyData, expectedEncrypted));

    TestConstDecrypt( "AES-CBC 128", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc128, AesConstants.EncryptedCbc128A );
    TestConstDecrypt( "AES-CBC 128", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc128, AesConstants.EncryptedCbc128B );
    TestConstDecrypt( "AES-CBC 256", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc256, AesConstants.EncryptedCbc256A );
    TestConstDecrypt( "AES-CBC 256", Algorithm.Aes.Cbc.Import, AesConstants.KeyCbc256, AesConstants.EncryptedCbc256B );
  
    void TestConstDecrypt<T>(string description, IKeyManagerImportRaw<T> importAlgo, string keyData,
      string encrypted) where T : IEncryptDecrypt =>
      suite.Test($"Const Decrypt {description}", () => SymConstDecrypt(importAlgo, keyData, encrypted));
    
    
    TestAsymEncryptDecrypt( "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1, 256 );
    TestAsymEncryptDecrypt( "RSA-OAEP 512", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Import, RsaConstants.PrivateKey1, RsaConstants.PublicKey1, 256 );
    TestAsymEncryptDecrypt( "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.PublicKey2, 256 );
  
    void TestAsymEncryptDecrypt<TPublic,TPrivate>(string description, IKeyManagerImport<TPublic,TPrivate> importAlgo,
      string privateKeyData, string publicKeyData, int expectedEncrypted)
      where TPrivate : IDecrypt where TPublic : IEncrypt =>
      suite.Test($"Encrypt Decrypt {description}", () => base.AsymEncryptDecrypt(importAlgo, privateKeyData, publicKeyData, expectedEncrypted));
    
    
    TestAsymConstDecrypt( "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.EncryptedKey1_Native_256 );
    TestAsymConstDecrypt( "RSA-OAEP 512", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Import, RsaConstants.PrivateKey1, RsaConstants.EncryptedKey1_Native_512 );
    TestAsymConstDecrypt( "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.EncryptedKey2_Native_256 );
    TestAsymConstDecrypt( "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey1, RsaConstants.EncryptedKey1_Browser_256 );
    TestAsymConstDecrypt( "RSA-OAEP 512", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha512].Import, RsaConstants.PrivateKey1, RsaConstants.EncryptedKey1_Browser_512 );
    TestAsymConstDecrypt( "RSA-OAEP 256", Algorithm.Rsa.Oaep[Algorithm.Digest.Sha256].Import, RsaConstants.PrivateKey2, RsaConstants.EncryptedKey2_Browser_256 );

    void TestAsymConstDecrypt<TPublic,TPrivate>(string description, IKeyManagerImport<TPublic,TPrivate> importAlgo,
      string privateKeyData, string encrypted)
      where TPrivate : IDecrypt where TPublic : IEncrypt =>
      suite.Test($"Const Decrypt {description}", () => base.AsymConstDecrypt(importAlgo, privateKeyData, encrypted));

  }
  
}