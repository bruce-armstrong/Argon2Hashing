using System;
using System.Diagnostics;
using System.Linq;
using Argon2Hashing;

// Self-checking test runner: exits 0 when everything passes, 1 otherwise.
internal static class Program
{
    private static int _failures;

    private static int Main()
    {
        Console.WriteLine("Argon2Hashing tests (" + System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription + ")");

        // RFC 9106 section 5 test vectors: m=32 KiB, t=3, p=4, 32-byte tag, with secret and associated data.
        byte[] pwd = Enumerable.Repeat((byte)0x01, 32).ToArray();
        byte[] salt = Enumerable.Repeat((byte)0x02, 16).ToArray();
        byte[] secret = Enumerable.Repeat((byte)0x03, 8).ToArray();
        byte[] ad = Enumerable.Repeat((byte)0x04, 12).ToArray();

        CheckVector("RFC 9106 Argon2d", Argon2Type.Argon2d, pwd, salt, secret, ad,
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");
        CheckVector("RFC 9106 Argon2i", Argon2Type.Argon2i, pwd, salt, secret, ad,
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");
        CheckVector("RFC 9106 Argon2id", Argon2Type.Argon2id, pwd, salt, secret, ad,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

        // Reference CLI example from the phc-winner-argon2 README:
        //   echo -n "password" | argon2 somesalt -t 2 -m 16 -p 4 -l 24
        var h = new Argon2Hasher();
        Check("libargon2 README hash verifies",
            h.VerifyPassword("password", "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"));
        Check("libargon2 README hash rejects wrong password",
            !h.VerifyPassword("Password", "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"));

        // Round trip with defaults (argon2id, m=64 MiB, t=3, p=4)
        var sw = Stopwatch.StartNew();
        string enc = h.HashPassword("correct horse battery staple");
        sw.Stop();
        Console.WriteLine("  default hash took " + sw.ElapsedMilliseconds + " ms: " + enc);
        Check("default hash has PHC prefix", enc.StartsWith("$argon2id$v=19$m=65536,t=3,p=4$"));
        Check("verify correct password", h.VerifyPassword("correct horse battery staple", enc));
        Check("reject wrong password", !h.VerifyPassword("correct horse battery stapler", enc) && h.GetLastError() == "");
        Check("salts are random", enc != h.HashPassword("correct horse battery staple"));
        Check("no rehash needed with same settings", !h.NeedsRehash(enc));

        // Unicode password
        string uni = h.HashPassword("pässwörd-密码-🔐");
        Check("unicode round trip", h.VerifyPassword("pässwörd-密码-🔐", uni));

        // Settings
        Check("SetParameters valid", h.SetParameters(19456, 2, 1));
        Check("rehash needed after settings change", h.NeedsRehash(enc));
        Check("old hash still verifies after settings change", h.VerifyPassword("correct horse battery staple", enc));
        Check("SetParameters rejects tiny memory", !h.SetParameters(4, 1, 1) && h.GetLastError().Length > 0);
        Check("SetVariant argon2i", h.SetVariant("argon2i") && h.GetVariant() == "argon2i");
        Check("SetVariant rejects junk", !h.SetVariant("bcrypt"));
        string ienc = h.HashPassword("x");
        Check("argon2i prefix", ienc.StartsWith("$argon2i$v=19$m=19456,t=2,p=1$"));
        Check("argon2i verify", h.VerifyPassword("x", ienc));

        // Secret / pepper
        h.SetVariant("argon2id");
        h.SetSecret("server-pepper");
        string peppered = h.HashPassword("pw");
        Check("pepper verify", h.VerifyPassword("pw", peppered));
        h.SetSecret("");
        Check("pepper required", !h.VerifyPassword("pw", peppered));

        // Malformed input never throws
        Check("empty hash", !h.VerifyPassword("pw", "") && h.GetLastError().Length > 0);
        Check("garbage hash", !h.VerifyPassword("pw", "$2y$10$abcdefghijklmnopqrstuv") && h.GetLastError().Length > 0);
        Check("null inputs", !h.VerifyPassword(null, null));
        Check("huge memory rejected", !h.VerifyPassword("pw", "$argon2id$v=19$m=99999999,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA"));
        Check("IsValidHash", h.IsValidHash(enc) && !h.IsValidHash("nope"));
        Check("version", h.GetLibraryVersion() == "1.0.0");

        Console.WriteLine(_failures == 0 ? "ALL TESTS PASSED" : _failures + " TEST(S) FAILED");
        return _failures == 0 ? 0 : 1;
    }

    private static void CheckVector(string name, Argon2Type type, byte[] pwd, byte[] salt, byte[] secret, byte[] ad, string expectedHex)
    {
        byte[] tag = Argon2Core.Hash(type, pwd, salt, secret, ad, 3, 32, 4, 32);
        string hex = BitConverter.ToString(tag).Replace("-", "").ToLowerInvariant();
        Check(name, hex == expectedHex, hex);
    }

    private static void Check(string name, bool ok, string detail = null)
    {
        Console.WriteLine((ok ? "  PASS  " : "  FAIL  ") + name + (ok || detail == null ? "" : "  got " + detail));
        if (!ok) _failures++;
    }
}
