using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;

namespace FluentCrossPlatformCrypto.Internals.Browser;

[SupportedOSPlatform("browser")]
internal static partial class Interop
{
  static Interop()
  {
    Eval("window.identity=function (x) { return x; }");
    Eval("window.toUint8Array=function (x) { return new Uint8Array(x); }");
    Eval("window.fromUint8Array=function (x) { return x.buffer; }");
    
    // Unless I'm missing something, there is no direct way of exporting as SPKI the public key of a PKCS#8 import
    // So we convert a private key to public key by
    // - exporting it as JWK
    // - remove the private part from the JWK
    // - import the JWK as a public key
    Eval(@"
window.privateToPublic = async function (privateKey,algorithm,usages) {
  const jwkPrivateData = await crypto.subtle.exportKey('jwk', privateKey);
  const jwkPublicData = { ...jwkPrivateData, key_ops: usages, d: undefined };
  const jwkPublicKey = await crypto.subtle.importKey('jwk', jwkPublicData, algorithm, true, usages);
  return jwkPublicKey;
}");
  }
  
  [JSImport("globalThis.eval")]
  public static partial JSObject Eval(string eval);
  
  [JSImport("globalThis.console.log")]
  public static partial void Log(JSObject obj);

  [JSImport("globalThis.identity")]
  public static partial string[] GetAsStringArray(JSObject obj);

  [JSImport("globalThis.identity")]
  public static partial JSObject CreateStringArray(string[] array);

  [JSImport("globalThis.JSON.stringify")]
  public static partial string Stringify(JSObject obj);

  [JSImport("globalThis.crypto.getRandomValues")]
  internal static partial JSObject GetRandomValues(JSObject array);

  [JSImport("globalThis.crypto.subtle.digest")]
  internal static partial Task<JSObject> Digest(string algorithm, JSObject data);

  [JSImport("globalThis.crypto.subtle.importKey")]
  internal static partial Task<JSObject> ImportKey(string format, JSObject data, JSObject algorithm, bool isExtractable, string[] usages);

  [JSImport("globalThis.crypto.subtle.generateKey")]
  internal static partial Task<JSObject> GenerateKey(JSObject algorithm, bool isExtractable, string[] usages);

  [JSImport("globalThis.crypto.subtle.exportKey")]
  internal static partial Task<JSObject> ExportKey(string format, JSObject key);

  [JSImport("globalThis.fromUint8Array")]
  internal static partial JSObject FromUint8Array(byte[] data);

  [JSImport("globalThis.toUint8Array")]
  internal static partial byte[] ToUint8Array(JSObject buffer);

  [JSImport("globalThis.toUint8Array")]
  internal static partial JSObject CreateUint8Array(int length);

  [JSImport("globalThis.privateToPublic")]
  internal static partial Task<JSObject> PrivateToPublic(JSObject privateKey, JSObject algorithm, string[] usages);

  [JSImport("globalThis.crypto.subtle.encrypt")]
  internal static partial Task<JSObject> Encrypt(JSObject algorithm, JSObject key, JSObject data);
  
  [JSImport("globalThis.crypto.subtle.decrypt")]
  internal static partial Task<JSObject> Decrypt(JSObject algorithm, JSObject key, JSObject data);

  [JSImport("globalThis.crypto.subtle.sign")]
  internal static partial Task<JSObject> Sign(JSObject algorithm, JSObject key, JSObject data);
  
  [JSImport("globalThis.crypto.subtle.verify")]
  internal static partial Task<bool> Verify(JSObject algorithm, JSObject key, JSObject signature, JSObject data);

  [JSImport("globalThis.crypto.subtle.deriveBits")]
  internal static partial Task<JSObject> DeriveBits(JSObject algorithm, JSObject key, int length);
}