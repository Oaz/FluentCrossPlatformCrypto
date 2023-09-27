namespace FluentCrossPlatformCrypto.Tests.Browser.TestFramework;

public class Suite
{
  private readonly List<(string Name,Func<Task> Code)> _tests = new ();

  public void Test(string name, Action code)
  {
    _tests.Add((name,() => Task.Run(code)));
  }

  public void Test(string name, Func<Task> code)
  {
    _tests.Add((name,code));
  }

  public async Task Run()
  {
    Console.WriteLine($"> Test suite - {_tests.Count} tests");
    var passed = 0;
    var failed = 0;
    var aborted = 0;
    foreach (var test in _tests)
    {
      try
      {
        Console.WriteLine($"> {test.Name}");
        await test.Code();
        Console.WriteLine($"> {test.Name} PASSED");
        passed++;
      }
      catch (AssertException e)
      {
        Console.WriteLine($"> {test.Name} FAILED: {e.Message}");
        failed++;
      }
      catch (Exception e)
      {
        Console.WriteLine($"> {test.Name} ABORT: {e.Message}");
        Console.WriteLine(e.StackTrace);
        aborted++;
      }
    }
    Console.WriteLine("> Test suite COMPLETE");
    Console.WriteLine($"> Passed: {passed}");
    Console.WriteLine($"> Failed: {failed}");
    Console.WriteLine($"> Aborted: {aborted}");
  }
}