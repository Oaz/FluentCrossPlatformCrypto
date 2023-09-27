using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Native;

public class Asserts : IAssert
{
  public void AreEqual<T>(T actual, T expected)
    => Assert.That(actual, Is.EqualTo(expected));

  public void AreSameData(byte[] actual, byte[] expected)
    => Assert.That(actual.ToBase64(), Is.EqualTo(expected.ToBase64()));
}