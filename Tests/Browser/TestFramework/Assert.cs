using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Browser.TestFramework;

public class Assert : IAssert
{
  public void AreEqual<T>(T actual, T expected)
  {
    if (!actual!.Equals(expected))
      throw new AssertException($"Expected [{expected}] but was [{actual}]");
  }

  public void AreSameData(byte[] actual, byte[] expected)
  {
    AreEqual(actual.ToBase64(), expected.ToBase64());
  }
}

public class AssertException : Exception
{
  public AssertException(string message) : base(message)
  {
    
  }
}
