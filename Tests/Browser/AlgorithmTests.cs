using FluentCrossPlatformCrypto.Tests.Browser.TestFramework;

namespace FluentCrossPlatformCrypto.Tests.Browser;

public class AlgorithmTests : Helpers.AlgorithmTests
{
  public void Add(Suite suite)
  {
    Assert = new Assert();

    suite.Test("Algorithm types", () =>
    {
      foreach (var example in Examples)
      {
        var algorithm = example[0];
        var type = (Type)example[1];
        Assert.AreEqual( type.IsInstanceOfType(algorithm), true);
      }
    });
  }
}