using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Argon2Hashing
{
    /// <summary>
    /// Argon2 password hashing for PowerBuilder (and any other .NET caller).
    ///
    /// Designed for the PowerBuilder .NET DLL Importer:
    ///   * public, non-static class with a public parameterless constructor
    ///   * public instance methods only - no overloads, properties, generics, optional parameters or out/ref
    ///   * only string, int and bool in signatures (PB string, long and boolean)
    ///   * methods never throw: failures return "" / false / -1 and the reason is available from GetLastError()
    ///
    /// Hashes are stored in the standard PHC string format used by libargon2, PHP, Python argon2-cffi, etc.:
    ///   $argon2id$v=19$m=65536,t=3,p=4$&lt;salt-base64&gt;$&lt;hash-base64&gt;
    /// so they are interchangeable with other Argon2 implementations.
    /// </summary>
    public class Argon2Hasher
    {
        // Upper bound on memory cost, to keep a 32-bit PowerBuilder process (and a hostile stored hash) from
        // exhausting the address space. 1 GiB.
        private const int MaxMemoryKiB = 1024 * 1024;

        private Argon2Type _type = Argon2Type.Argon2id;
        private int _memoryKiB = 65536;   // 64 MiB  \
        private int _iterations = 3;      //          > RFC 9106 second recommended option
        private int _parallelism = 4;     //         /
        private int _hashLength = 32;
        private int _saltLength = 16;
        private byte[] _secret = new byte[0];
        private string _lastError = "";

        public Argon2Hasher()
        {
        }

        // ------------------------------------------------------------------ hashing

        /// <summary>Hashes a password with a new random salt and the current settings. Returns a PHC string, or "" on error.</summary>
        public string HashPassword(string password)
        {
            _lastError = "";
            try
            {
                byte[] salt = new byte[_saltLength];
                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);

                byte[] pwd = Encoding.UTF8.GetBytes(password ?? "");
                byte[] tag;
                try
                {
                    tag = Argon2Core.Hash(_type, pwd, salt, _secret, null, _iterations, _memoryKiB, _parallelism, _hashLength);
                }
                finally
                {
                    Array.Clear(pwd, 0, pwd.Length);
                }
                return Encode(_type, _memoryKiB, _iterations, _parallelism, salt, tag);
            }
            catch (OutOfMemoryException)
            {
                _lastError = "Not enough memory for a memory cost of " + _memoryKiB + " KiB.";
                return "";
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                return "";
            }
        }

        /// <summary>
        /// Checks a password against a PHC-format Argon2 hash (argon2id, argon2i or argon2d, any parameters).
        /// Returns false for a wrong password or an invalid hash; GetLastError() is "" for a simple mismatch.
        /// </summary>
        public bool VerifyPassword(string password, string encodedHash)
        {
            _lastError = "";
            try
            {
                if (!TryDecode(encodedHash, out var p)) return false;

                byte[] pwd = Encoding.UTF8.GetBytes(password ?? "");
                byte[] tag;
                try
                {
                    tag = Argon2Core.Hash(p.Type, pwd, p.Salt, _secret, null, p.Iterations, p.MemoryKiB, p.Parallelism, p.Hash.Length);
                }
                finally
                {
                    Array.Clear(pwd, 0, pwd.Length);
                }
                return FixedTimeEquals(tag, p.Hash);
            }
            catch (OutOfMemoryException)
            {
                _lastError = "Not enough memory to verify this hash.";
                return false;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                return false;
            }
        }

        /// <summary>
        /// True when a stored hash was made with different settings than the current ones (variant, memory,
        /// iterations, parallelism, hash or salt length), so it should be re-hashed after a successful login.
        /// Also true for a hash that cannot be parsed.
        /// </summary>
        public bool NeedsRehash(string encodedHash)
        {
            _lastError = "";
            if (!TryDecode(encodedHash, out var p)) return true;
            return p.Type != _type || p.MemoryKiB != _memoryKiB || p.Iterations != _iterations ||
                   p.Parallelism != _parallelism || p.Hash.Length != _hashLength || p.Salt.Length != _saltLength;
        }

        /// <summary>True when the text is a well-formed Argon2 PHC string this library can verify.</summary>
        public bool IsValidHash(string encodedHash)
        {
            _lastError = "";
            return TryDecode(encodedHash, out _);
        }

        // ------------------------------------------------------------------ settings

        /// <summary>Sets memory cost (KiB), iterations (time cost) and parallelism (lanes). Returns false if out of range.</summary>
        public bool SetParameters(int memoryKiB, int iterations, int parallelism)
        {
            _lastError = "";
            if (parallelism < 1 || parallelism > 255) return Fail("Parallelism must be between 1 and 255.");
            if (iterations < 1 || iterations > 1000) return Fail("Iterations must be between 1 and 1000.");
            if (memoryKiB < 8 * parallelism) return Fail("Memory must be at least 8 KiB per lane (" + 8 * parallelism + " KiB).");
            if (memoryKiB > MaxMemoryKiB) return Fail("Memory must not exceed " + MaxMemoryKiB + " KiB.");
            _memoryKiB = memoryKiB;
            _iterations = iterations;
            _parallelism = parallelism;
            return true;
        }

        /// <summary>Sets the variant: "argon2id" (recommended), "argon2i" or "argon2d".</summary>
        public bool SetVariant(string variant)
        {
            _lastError = "";
            if (!TryParseType((variant ?? "").Trim().ToLowerInvariant(), out var t))
                return Fail("Unknown variant '" + variant + "'. Use argon2id, argon2i or argon2d.");
            _type = t;
            return true;
        }

        /// <summary>Sets the hash (tag) length in bytes, 16..512. Default 32.</summary>
        public bool SetHashLength(int bytes)
        {
            _lastError = "";
            if (bytes < 16 || bytes > 512) return Fail("Hash length must be between 16 and 512 bytes.");
            _hashLength = bytes;
            return true;
        }

        /// <summary>Sets the random salt length in bytes, 8..64. Default 16.</summary>
        public bool SetSaltLength(int bytes)
        {
            _lastError = "";
            if (bytes < 8 || bytes > 64) return Fail("Salt length must be between 8 and 64 bytes.");
            _saltLength = bytes;
            return true;
        }

        /// <summary>
        /// Optional server-side secret ("pepper"), Argon2's K input. It is NOT stored in the hash, so the same
        /// secret must be set before verifying. Pass "" to clear.
        /// </summary>
        public void SetSecret(string secret)
        {
            _lastError = "";
            Array.Clear(_secret, 0, _secret.Length);
            _secret = Encoding.UTF8.GetBytes(secret ?? "");
        }

        public int GetMemoryKiB() => _memoryKiB;
        public int GetIterations() => _iterations;
        public int GetParallelism() => _parallelism;
        public int GetHashLength() => _hashLength;
        public int GetSaltLength() => _saltLength;
        public string GetVariant() => TypeName(_type);

        /// <summary>Reason for the last failure, or "" if the last call succeeded.</summary>
        public string GetLastError() => _lastError;

        /// <summary>Library version, e.g. "1.0.0".</summary>
        public string GetLibraryVersion()
        {
            var v = typeof(Argon2Hasher).Assembly.GetName().Version;
            return v == null ? "" : v.ToString(3);
        }

        // ------------------------------------------------------------------ PHC string format

        private sealed class Decoded
        {
            public Argon2Type Type;
            public int MemoryKiB, Iterations, Parallelism;
            public byte[] Salt, Hash;
        }

        private static string Encode(Argon2Type type, int m, int t, int p, byte[] salt, byte[] hash)
        {
            return "$" + TypeName(type) + "$v=" + Argon2Core.Version.ToString(CultureInfo.InvariantCulture) +
                   "$m=" + m.ToString(CultureInfo.InvariantCulture) +
                   ",t=" + t.ToString(CultureInfo.InvariantCulture) +
                   ",p=" + p.ToString(CultureInfo.InvariantCulture) +
                   "$" + ToB64(salt) + "$" + ToB64(hash);
        }

        private bool TryDecode(string encoded, out Decoded result)
        {
            result = null;
            if (string.IsNullOrWhiteSpace(encoded)) return Fail("Hash is empty.");

            // "", type, v=19, m=..,t=..,p=.., salt, hash
            string[] parts = encoded.Trim().Split('$');
            if (parts.Length != 6 || parts[0].Length != 0) return Fail("Not an Argon2 PHC hash string.");
            if (!TryParseType(parts[1], out var type)) return Fail("Unknown Argon2 variant '" + parts[1] + "'.");
            if (parts[2] != "v=19") return Fail("Unsupported Argon2 version '" + parts[2] + "' (only v=19 / 1.3).");

            int m = -1, t = -1, p = -1;
            foreach (string kv in parts[3].Split(','))
            {
                int eq = kv.IndexOf('=');
                if (eq <= 0 || !int.TryParse(kv.Substring(eq + 1), NumberStyles.None, CultureInfo.InvariantCulture, out int val))
                    return Fail("Malformed parameter '" + kv + "'.");
                switch (kv.Substring(0, eq))
                {
                    case "m": m = val; break;
                    case "t": t = val; break;
                    case "p": p = val; break;
                    default: return Fail("Unsupported parameter '" + kv + "'.");
                }
            }
            if (m < 0 || t < 0 || p < 0) return Fail("Hash is missing m, t or p.");
            if (p < 1 || p > 255 || t < 1 || t > 1000 || m < 8 * p) return Fail("Hash parameters are out of range.");
            if (m > MaxMemoryKiB) return Fail("Hash memory cost " + m + " KiB exceeds the limit of " + MaxMemoryKiB + " KiB.");

            byte[] salt = FromB64(parts[4]);
            byte[] hash = FromB64(parts[5]);
            if (salt == null || salt.Length < 8) return Fail("Invalid salt.");
            if (hash == null || hash.Length < 4) return Fail("Invalid hash value.");

            result = new Decoded { Type = type, MemoryKiB = m, Iterations = t, Parallelism = p, Salt = salt, Hash = hash };
            return true;
        }

        private static bool TryParseType(string name, out Argon2Type type)
        {
            switch (name)
            {
                case "argon2id": type = Argon2Type.Argon2id; return true;
                case "argon2i": type = Argon2Type.Argon2i; return true;
                case "argon2d": type = Argon2Type.Argon2d; return true;
                default: type = Argon2Type.Argon2id; return false;
            }
        }

        private static string TypeName(Argon2Type t) =>
            t == Argon2Type.Argon2i ? "argon2i" : t == Argon2Type.Argon2d ? "argon2d" : "argon2id";

        // PHC uses standard base64 without '=' padding.
        private static string ToB64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

        private static byte[] FromB64(string s)
        {
            if (string.IsNullOrEmpty(s) || s.IndexOf('=') >= 0 || s.Length % 4 == 1) return null;
            try { return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=')); }
            catch (FormatException) { return null; }
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private bool Fail(string message)
        {
            _lastError = message;
            return false;
        }
    }
}
