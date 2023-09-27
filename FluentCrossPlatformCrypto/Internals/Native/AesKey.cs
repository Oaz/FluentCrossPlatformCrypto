using System.Runtime.Versioning;
using System.Security.Cryptography;
using MemoryStream = System.IO.MemoryStream;

namespace FluentCrossPlatformCrypto.Internals.Native;

[UnsupportedOSPlatform("browser")]
internal class AesKey : IEncryptDecrypt
{
  private readonly SymmetricAlgorithm _key;

  public AesKey(SymmetricAlgorithm key)
  {
    _key = key;
  }

  public KeyType Type => KeyType.Secret;
  
  public async Task<string> Decrypt(byte[] data)
  {
    using var aes = Aes.Create();
    using var ms = new MemoryStream(data);
    var iv = new byte[aes.IV.Length];
    var read = await ms.ReadAsync(iv);
    await using var cs = new CryptoStream(ms, aes.CreateDecryptor(_key.Key, iv), CryptoStreamMode.Read);
    using var sr = new StreamReader(cs);
    return await sr.ReadToEndAsync();
  }

  public async Task<byte[]> Encrypt(string message)
  {
    using var ms = new MemoryStream();
    await ms.WriteAsync(_key.IV);
    await using var cs = new CryptoStream(ms, _key.CreateEncryptor(), CryptoStreamMode.Write);
    await using var sw = new StreamWriter(cs);
    await sw.WriteAsync(message);
    await sw.FlushAsync();
    await cs.FlushFinalBlockAsync();
    ms.Seek(0, SeekOrigin.Begin);
    var result = new byte[ms.Length];
    var read = await ms.ReadAsync(result, 0, result.Length);
    return result;
  }

  public Task<byte[]> ExportRaw()
  {
    return Task.FromResult(_key.Key);
  }
}
