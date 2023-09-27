namespace FluentCrossPlatformCrypto;

public static class Random
{
  public static byte[] GetValues(uint length) => Internals.IEngine.Singleton.GetRandomValues(length);
}

public interface IKey
{
  KeyType Type { get; }
}

[Flags]
public enum KeyType
{
  Secret = 1,
  Private = 2,
  Public = 4,
}

public interface IKeyPair<out TPublic, out TPrivate>
{
  TPublic PublicKey { get; }
  TPrivate PrivateKey { get; }
}

public interface IDigest
{
  string Name { get; }
  uint Length { get; }
  Task<byte[]> Digest(byte[] message);
  Task<byte[]> Digest(string message);
}

#region Key Generate/Import

public interface IKeyManagerGenerate<T>
{
  Task<T> Key();
}

public interface IKeyManagerImportRaw<T>
{
  Task<T> Raw(byte[] data);
}

public interface IKeyManagerImportText<T>
{
  Task<T> Text(string data);
}

public interface IKeyManagerImport<TPublic,TPrivate>
{
  Task<TPrivate> Pkcs8(byte[] data);
  Task<TPublic> Spki(byte[] data);
}

#endregion

#region Key Export

public interface IExportRaw
{
  Task<byte[]> ExportRaw();
}

public interface IExportPrivate : IExportPublic
{
  Task<byte[]> ExportPkcs8();
}

public interface IExportPublic
{
  Task<byte[]> ExportSpki();
}

#endregion

#region Encrypt/Decrypt

public interface IEncrypt : IKey
{
  Task<byte[]> Encrypt(string message);
}

public interface IDecrypt : IKey
{
  Task<string> Decrypt(byte[] data);
}

public interface IEncryptExport : IEncrypt, IExportPublic { }
public interface IDecryptExport : IDecrypt, IExportPrivate { }
public interface IEncryptDecrypt : IEncrypt, IDecrypt, IExportRaw { }

#endregion

#region Sign/Verify

public interface IVerify : IKey
{
  Task<bool> Verify(byte[] data, byte[] signature);
}
public interface IVerifyExportPublic : IVerify, IExportPublic { }
public interface IEcVerifyExportPublic : IVerifyExportPublic { }

public interface ISign : IKey
{
  Task<byte[]> Sign(byte[] data);
}
public interface ISignExportPrivate : ISign, IExportPrivate { }
public interface ISignVerify : ISign, IVerify, IExportRaw { }

#endregion

#region Key Derivation

public interface IDerive
{
  Task<byte[]> Derive();
  Task<IEncryptDecrypt> DeriveToAes();
  Task<ISignVerify> DeriveToHmac();
}

public interface IDerivePbkdf2 : IExportRaw
{
  IDerive With(uint iterations, byte[]? salt = default);
}

public interface IDeriveHkdf : IExportRaw
{
  IDerive With(string info, byte[]? salt = default);
}

public interface IEcDeriveExportPrivate : IExportPrivate
{
  IDerive With(IEcVerifyExportPublic otherPublicKey);
}

#endregion