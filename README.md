# Argon2 password hashing for PowerBuilder

A C# Argon2 assembly built to work with the PowerBuilder **.NET DLL Importer**, plus a small PowerBuilder 2025 demo app that uses it.

- **`Argon2Hashing.dll`**: Argon2id / Argon2i / Argon2d (RFC 9106, version 1.3) in plain managed code. It has **no NuGet dependencies**, so you deploy one DLL. It is checked against the RFC 9106 test vectors and the libargon2 reference hash.
- **Hashes use the standard PHC string format** (`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`). That is the same format libargon2, PHP `password_hash`, Python `argon2-cffi`, Node `argon2` and others use, so hashes made by any of them work in both directions.
- **`Argon2Demo.pbsln`**: the PowerBuilder 2025 demo. It hashes a password, verifies one, applies settings and checks whether a hash needs rehashing.

```
Argon2Hashing/
├─ dotnet/Argon2Hashing/          C# library (net8.0 + net48)
│   ├─ Argon2Hasher.cs            public API used from PowerBuilder
│   ├─ Argon2Core.cs              Argon2 algorithm
│   └─ Blake2b.cs                 BLAKE2b (used by Argon2)
├─ dotnet/Argon2Hashing.Tests/    test runner (RFC vectors, round trips, error cases)
├─ Argon2Demo.pbsln / .pbproj     PowerBuilder 2025 solution
├─ PowerBuilder/argon2demo.pbl/
│   ├─ nvo_argon2hasher.sru       .NET proxy (the object the .NET DLL Importer generates)
│   ├─ w_argon2_demo.srw          demo window
│   ├─ n_cst_selftest.sru         headless end-to-end test (argon2demo.exe /selftest)
│   └─ argon2demo.sra             application object
└─ build.ps1                      builds everything; -Test runs both test suites
```

## Build and run

```bash
pwsh -File build.ps1 -Test
```

This builds the DLL and runs the .NET tests. It then compiles the PowerBuilder app with PBAutoBuild into `build\argon2demo\`, copies `Argon2Hashing.dll` next to the exe, and runs `argon2demo.exe /selftest`. The self-test calls the DLL through the PowerBuilder proxy. Add `-Platform 64` for a 64-bit exe.

To run from the IDE, open `Argon2Demo.pbsln` in PowerBuilder 2025. `build.ps1` also copies the DLL into the solution folder, where the IDE looks for it.

**Runtime requirement:** the demo loads the **net8.0** build. The .NET 8 runtime for the app's bitness must be installed: x86 for a 32-bit exe, x64 for a 64-bit exe.

## Importing with the .NET DLL Importer

`nvo_argon2hasher` is already in the library. To regenerate it, or to import the DLL into your own app:

1. Run `dotnet build dotnet\Argon2Hashing -c Release`.
2. In PowerBuilder go to **Tools → .NET DLL Importer**.
3. Source assembly: choose one build.
   - `dotnet\Argon2Hashing\bin\Release\net8.0\Argon2Hashing.dll` with framework **.NET Core / .NET**. This needs PB 2022 R2 or later, and the proxy uses `LoadWithDotNetCore`.
   - `...\net48\Argon2Hashing.dll` with framework **.NET Framework**. This needs PB 2019 R3 or later, the proxy uses `LoadWithDotNetFramework`, and no extra runtime is needed.
4. Select class `Argon2Hashing.Argon2Hasher` and all of its methods. Choose the target library. Name the proxy `nvo_argon2hasher` to replace the included one.
5. Deploy `Argon2Hashing.dll` next to your exe. With net8.0, also deploy `Argon2Hashing.deps.json`.

### Why it imports cleanly

`Argon2Hasher` follows the rules the importer handles without problems:

- It is a public, non-static class with a public parameterless constructor.
- It has public **instance** methods only. There are no overloads, properties, generics, optional parameters, `out`/`ref` parameters or events.
- Signatures use only `string`, `int` and `bool` (PowerBuilder `string`, `long` and `boolean`).
- **Methods never throw.** On failure they return `""`, `false` or `-1`, and `GetLastError()` gives the reason. The proxy's `ue_error` / `is_ErrorText` only fire when the assembly cannot be loaded.

## API

| PowerBuilder proxy | .NET method | Notes |
|---|---|---|
| `of_hashpassword(password)` → string | `HashPassword` | New random salt each call. Returns the PHC string, or `""` on error. |
| `of_verifypassword(password, hash)` → boolean | `VerifyPassword` | Reads the variant, parameters and salt from the hash. Compares in constant time. |
| `of_needsrehash(hash)` → boolean | `NeedsRehash` | True if the hash was made with different settings than the current ones. |
| `of_isvalidhash(hash)` → boolean | `IsValidHash` | |
| `of_setparameters(memoryKiB, iterations, parallelism)` → boolean | `SetParameters` | Memory 8·p KiB to 1 GiB, iterations 1–1000, parallelism 1–255. |
| `of_setvariant("argon2id" \| "argon2i" \| "argon2d")` → boolean | `SetVariant` | |
| `of_sethashlength(bytes)` / `of_setsaltlength(bytes)` → boolean | | Hash 16–512 bytes (default 32). Salt 8–64 bytes (default 16). |
| `of_setsecret(pepper)` | `SetSecret` | Optional server-side pepper (Argon2's secret K). It is **not** stored in the hash, so set the same value before verifying. |
| `of_get…()` | `GetMemoryKiB`, `GetIterations`, `GetParallelism`, `GetHashLength`, `GetSaltLength`, `GetVariant`, `GetLastError`, `GetLibraryVersion` | |

The defaults are **argon2id, m = 64 MiB, t = 3, p = 4, 16-byte salt, 32-byte hash**. That is the second recommended setting in RFC 9106, and it takes about 0.2 s per hash on a modern PC. OWASP's lower-memory minimum is `of_setparameters(19456, 2, 1)`.

### Typical login code

```powerscript
nvo_argon2hasher lnv_argon2
lnv_argon2 = create nvo_argon2hasher

// Registration: store ls_hash (about 100 chars) in a varchar(255) column
ls_hash = lnv_argon2.of_hashpassword(ls_password)

// Login
if lnv_argon2.of_verifypassword(ls_password, ls_stored_hash) then
    if lnv_argon2.of_needsrehash(ls_stored_hash) then
        // settings were raised since this hash was made: upgrade it
        ls_new_hash = lnv_argon2.of_hashpassword(ls_password)   // save ls_new_hash
    end if
    // logged in
end if
```

PowerBuilder strings are passed to .NET as Unicode and hashed as UTF-8, the same as other Argon2 libraries. So non-ASCII passwords give interoperable hashes.

## License

MIT. See [LICENSE](LICENSE).
