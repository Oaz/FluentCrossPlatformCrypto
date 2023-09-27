namespace FluentCrossPlatformCrypto.Tests.Helpers;

public interface IAssert
{
  void AreEqual<T>(T actual, T expected);
  void AreSameData(byte[] actual, byte[] expected);
}