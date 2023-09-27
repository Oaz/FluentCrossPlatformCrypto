using FluentCrossPlatformCrypto.Tests.Helpers;

namespace FluentCrossPlatformCrypto.Tests.Native;

public class DigestTests : Helpers.DigestTests
{
  [SetUp]
  public void Init()
  {
    Assert = new Asserts();
  }
  
  [TestCaseSource(nameof(DigestCases))]
  public Task Compute(string description, IDigest algo, string expectedDigest)
    => base.Compute(algo, expectedDigest);

  public static object[] DigestCases =
  {
    new object[] { "SHA-1", Algorithm.Digest.Sha1,     DigestConstants.Sha1__ },
    new object[] { "SHA-256", Algorithm.Digest.Sha256, DigestConstants.Sha256 },
    new object[] { "SHA-384", Algorithm.Digest.Sha384, DigestConstants.Sha384 },
    new object[] { "SHA-512", Algorithm.Digest.Sha512, DigestConstants.Sha512 },
  };
}