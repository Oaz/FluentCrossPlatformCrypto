using FluentCrossPlatformCrypto.Tests.Browser.TestFramework;
using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Browser;

public class DigestTests : Helpers.DigestTests
{
  public void Add(Suite suite)
  {
    Assert = new Assert();
    
    TestCompute(Algorithm.Digest.Sha1,   DigestConstants.Sha1__);
    TestCompute(Algorithm.Digest.Sha256, DigestConstants.Sha256);
    TestCompute(Algorithm.Digest.Sha384, DigestConstants.Sha384);
    TestCompute(Algorithm.Digest.Sha512, DigestConstants.Sha512);

    void TestCompute(IDigest algo, string expectedDigest)
      => suite.Test($"Compute {algo.Name}", () => base.Compute(algo, expectedDigest));
  }
}