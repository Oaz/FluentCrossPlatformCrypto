namespace FluentCrossPlatformCrypto.Tests.Native;

public class AlgorithmTests : Helpers.AlgorithmTests
{
  [SetUp]
  public void Init()
  {
    Assert = new Asserts();
  }
  
  [TestCaseSource(nameof(Examples))]
  public void CheckType(object algorithm, Type type)
  {
    Assert.AreEqual( type.IsInstanceOfType(algorithm), true);
  }
}