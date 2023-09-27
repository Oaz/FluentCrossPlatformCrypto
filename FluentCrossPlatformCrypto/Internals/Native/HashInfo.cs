using System.Security.Cryptography;

namespace FluentCrossPlatformCrypto.Internals.Native;

internal class HashInfo
{
  public static HashInfo Get(IDigest hash) => HashInfos[hash];

  private static readonly Dictionary<IDigest, HashInfo> HashInfos = new()
  {
    { Algorithm.Digest.Sha1,   new HashInfo(HashAlgorithmName.SHA1,  RSAEncryptionPadding.OaepSHA1  ,key => new HMACSHA1(key),   40) },
    { Algorithm.Digest.Sha256, new HashInfo(HashAlgorithmName.SHA256,RSAEncryptionPadding.OaepSHA256,key => new HMACSHA256(key), 64) },
    { Algorithm.Digest.Sha384, new HashInfo(HashAlgorithmName.SHA384,RSAEncryptionPadding.OaepSHA384,key => new HMACSHA384(key), 96) },
    { Algorithm.Digest.Sha512, new HashInfo(HashAlgorithmName.SHA512,RSAEncryptionPadding.OaepSHA512,key => new HMACSHA512(key),128) },
  };
  
  public HashAlgorithmName Name { get; }
  public RSAEncryptionPadding EncryptionPadding { get; }
  public Func<byte[],HMAC> HmacCreate { get; }
  public uint HmacLength { get; }

  public HashInfo(HashAlgorithmName name, RSAEncryptionPadding encryptionPadding, Func<byte[], HMAC> hmacCreate, uint hmacLength)
  {
    Name = name;
    EncryptionPadding = encryptionPadding;
    HmacCreate = hmacCreate;
    HmacLength = hmacLength;
  }
}