using System.Dynamic;

namespace FluentCrossPlatformCrypto.Internals;

internal interface IEngine
{
  static IEngine Singleton { get; }
  static IEngine() =>
    Singleton = OperatingSystem.IsBrowser()
      ? BrowserEngine.Create()
      : NativeEngine.Create();
  byte[] GetRandomValues(uint length);
  Task<IKey> ImportKey(string format, ExpandoObject algorithmDetails, byte[] data);
  Task<IKey> GenerateKey(ExpandoObject algorithmDetails);
  Task<IKeyPair> GenerateKeyPair(ExpandoObject algorithmDetails);
  Task<byte[]> Digest(IDigest algorithm, byte[] message);

}

internal interface IKeyPair
{
  IKey? PublicKey { get; }
  IKey? PrivateKey { get; }
}