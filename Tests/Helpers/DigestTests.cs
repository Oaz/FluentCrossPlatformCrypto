namespace FluentCrossPlatformCrypto.Tests.Helpers;

public class DigestTests
{
  protected IAssert Assert = null!;

  protected async Task Compute(IDigest algo, string expectedDigest)
  {
    var digest = await algo.Digest(MiscConstants.Message);
    Assert.AreEqual(digest.ToBase64(), expectedDigest);
  }
}