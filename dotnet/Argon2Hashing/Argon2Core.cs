using System;
using System.Threading.Tasks;

namespace Argon2Hashing
{
    internal enum Argon2Type
    {
        Argon2d = 0,
        Argon2i = 1,
        Argon2id = 2
    }

    /// <summary>
    /// Argon2 version 1.3 (0x13) as specified in RFC 9106. Pure managed code, no dependencies.
    /// Lanes inside a slice are filled in parallel; the result is identical to sequential filling.
    /// </summary>
    internal static class Argon2Core
    {
        public const int Version = 0x13;
        private const int BlockWords = 128;   // 1024-byte block = 128 x 64-bit words
        private const int SyncPoints = 4;

        public static byte[] Hash(Argon2Type type, byte[] password, byte[] salt, byte[] secret, byte[] associatedData,
            int iterations, int memoryKiB, int parallelism, int tagLength)
        {
            password = password ?? new byte[0];
            salt = salt ?? new byte[0];
            secret = secret ?? new byte[0];
            associatedData = associatedData ?? new byte[0];

            if (parallelism < 1 || parallelism > 0xFFFFFF) throw new ArgumentOutOfRangeException(nameof(parallelism));
            if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
            if (tagLength < 4) throw new ArgumentOutOfRangeException(nameof(tagLength));
            if (memoryKiB < 8 * parallelism) throw new ArgumentOutOfRangeException(nameof(memoryKiB), "Memory must be at least 8 KiB per lane.");
            if (salt.Length < 8) throw new ArgumentException("Salt must be at least 8 bytes.", nameof(salt));

            // H0
            var h = new Blake2b(64);
            h.UpdateLE32((uint)parallelism);
            h.UpdateLE32((uint)tagLength);
            h.UpdateLE32((uint)memoryKiB);
            h.UpdateLE32((uint)iterations);
            h.UpdateLE32(Version);
            h.UpdateLE32((uint)type);
            h.UpdateLE32((uint)password.Length); h.Update(password);
            h.UpdateLE32((uint)salt.Length); h.Update(salt);
            h.UpdateLE32((uint)secret.Length); h.Update(secret);
            h.UpdateLE32((uint)associatedData.Length); h.Update(associatedData);
            byte[] h0 = h.Final();

            int segmentLength = memoryKiB / (SyncPoints * parallelism);
            int laneLength = segmentLength * SyncPoints;
            int blockCount = laneLength * parallelism;
            var memory = new ulong[(long)blockCount * BlockWords];

            try
            {
                // First two blocks of each lane
                var seed = new byte[72];
                Buffer.BlockCopy(h0, 0, seed, 0, 64);
                var blockBytes = new byte[1024];
                for (int lane = 0; lane < parallelism; lane++)
                {
                    WriteLE32(seed, 68, (uint)lane);
                    for (int col = 0; col < 2; col++)
                    {
                        WriteLE32(seed, 64, (uint)col);
                        byte[] hp = HPrime(1024, seed);
                        LoadBlock(memory, (lane * laneLength + col) * BlockWords, hp);
                        Array.Clear(hp, 0, hp.Length);
                    }
                }
                Array.Clear(seed, 0, seed.Length);

                var ctx = new Context
                {
                    Memory = memory,
                    Type = type,
                    Lanes = parallelism,
                    LaneLength = laneLength,
                    SegmentLength = segmentLength,
                    BlockCount = blockCount,
                    Passes = iterations
                };

                for (int pass = 0; pass < iterations; pass++)
                {
                    for (int slice = 0; slice < SyncPoints; slice++)
                    {
                        int p = pass, s = slice;
                        if (parallelism == 1)
                            FillSegment(ctx, p, 0, s);
                        else
                            Parallel.For(0, parallelism, lane => FillSegment(ctx, p, lane, s));
                    }
                }

                // Final block = XOR of the last block of every lane
                var final = new ulong[BlockWords];
                for (int lane = 0; lane < parallelism; lane++)
                {
                    int off = (lane * laneLength + laneLength - 1) * BlockWords;
                    for (int i = 0; i < BlockWords; i++) final[i] ^= memory[off + i];
                }
                for (int i = 0; i < BlockWords; i++) Blake2b.WriteLE64(blockBytes, i * 8, final[i]);
                byte[] tag = HPrime(tagLength, blockBytes);
                Array.Clear(blockBytes, 0, blockBytes.Length);
                Array.Clear(final, 0, final.Length);
                return tag;
            }
            finally
            {
                Array.Clear(memory, 0, memory.Length);
                Array.Clear(h0, 0, h0.Length);
            }
        }

        private sealed class Context
        {
            public ulong[] Memory;
            public Argon2Type Type;
            public int Lanes, LaneLength, SegmentLength, BlockCount, Passes;
        }

        private static void FillSegment(Context c, int pass, int lane, int slice)
        {
            ulong[] mem = c.Memory;
            var r = new ulong[BlockWords];
            var tmp = new ulong[BlockWords];

            bool dataIndependent = c.Type == Argon2Type.Argon2i ||
                                   (c.Type == Argon2Type.Argon2id && pass == 0 && slice < SyncPoints / 2);

            ulong[] addressBlock = null, inputBlock = null, zeroBlock = null;
            if (dataIndependent)
            {
                addressBlock = new ulong[BlockWords];
                inputBlock = new ulong[BlockWords];
                zeroBlock = new ulong[BlockWords];
                inputBlock[0] = (ulong)pass;
                inputBlock[1] = (ulong)lane;
                inputBlock[2] = (ulong)slice;
                inputBlock[3] = (ulong)c.BlockCount;
                inputBlock[4] = (ulong)c.Passes;
                inputBlock[5] = (ulong)c.Type;
            }

            int startIndex = 0;
            if (pass == 0 && slice == 0)
            {
                startIndex = 2;
                if (dataIndependent) NextAddresses(addressBlock, inputBlock, zeroBlock, r, tmp);
            }

            int currOffset = lane * c.LaneLength + slice * c.SegmentLength + startIndex;
            int prevOffset = (currOffset % c.LaneLength == 0) ? currOffset + c.LaneLength - 1 : currOffset - 1;

            for (int i = startIndex; i < c.SegmentLength; i++, currOffset++, prevOffset++)
            {
                if (currOffset % c.LaneLength == 1) prevOffset = currOffset - 1;

                ulong pseudoRand;
                if (dataIndependent)
                {
                    if (i % BlockWords == 0) NextAddresses(addressBlock, inputBlock, zeroBlock, r, tmp);
                    pseudoRand = addressBlock[i % BlockWords];
                }
                else
                {
                    pseudoRand = mem[prevOffset * BlockWords];
                }

                ulong refLane = (pseudoRand >> 32) % (ulong)c.Lanes;
                if (pass == 0 && slice == 0) refLane = (ulong)lane;

                int refIndex = IndexAlpha(c, pass, slice, i, (uint)pseudoRand, refLane == (ulong)lane);
                int refOffset = (int)refLane * c.LaneLength + refIndex;

                FillBlock(mem, prevOffset * BlockWords, mem, refOffset * BlockWords, mem, currOffset * BlockWords,
                    pass != 0, r, tmp);
            }
        }

        private static int IndexAlpha(Context c, int pass, int slice, int index, uint pseudoRand, bool sameLane)
        {
            long referenceAreaSize;
            if (pass == 0)
            {
                if (slice == 0)
                    referenceAreaSize = index - 1;
                else if (sameLane)
                    referenceAreaSize = (long)slice * c.SegmentLength + index - 1;
                else
                    referenceAreaSize = (long)slice * c.SegmentLength + (index == 0 ? -1 : 0);
            }
            else
            {
                if (sameLane)
                    referenceAreaSize = c.LaneLength - c.SegmentLength + index - 1;
                else
                    referenceAreaSize = c.LaneLength - c.SegmentLength + (index == 0 ? -1 : 0);
            }

            ulong relativePosition = pseudoRand;
            relativePosition = (relativePosition * relativePosition) >> 32;
            relativePosition = (ulong)referenceAreaSize - 1 - (((ulong)referenceAreaSize * relativePosition) >> 32);

            ulong startPosition = 0;
            if (pass != 0)
                startPosition = (slice == SyncPoints - 1) ? 0UL : (ulong)(slice + 1) * (ulong)c.SegmentLength;

            return (int)((startPosition + relativePosition) % (ulong)c.LaneLength);
        }

        private static void NextAddresses(ulong[] address, ulong[] input, ulong[] zero, ulong[] r, ulong[] tmp)
        {
            input[6]++;
            FillBlock(zero, 0, input, 0, address, 0, false, r, tmp);
            FillBlock(zero, 0, address, 0, address, 0, false, r, tmp);
        }

        /// <summary>next = G(prev, ref) (optionally XORed into the existing next block, Argon2 v1.3).</summary>
        private static void FillBlock(ulong[] prevArr, int prevOff, ulong[] refArr, int refOff,
            ulong[] nextArr, int nextOff, bool withXor, ulong[] r, ulong[] tmp)
        {
            for (int i = 0; i < BlockWords; i++)
            {
                r[i] = refArr[refOff + i] ^ prevArr[prevOff + i];
                tmp[i] = r[i];
            }
            if (withXor)
                for (int i = 0; i < BlockWords; i++) tmp[i] ^= nextArr[nextOff + i];

            // Rows: 8 x 16 consecutive words
            for (int i = 0; i < 8; i++)
            {
                int b = 16 * i;
                Round(r, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                    b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
            }
            // Columns: 8 x pairs of words strided by 16
            for (int i = 0; i < 8; i++)
            {
                int b = 2 * i;
                Round(r, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                    b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
            }

            for (int i = 0; i < BlockWords; i++) nextArr[nextOff + i] = tmp[i] ^ r[i];
        }

        private static void Round(ulong[] v, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7,
            int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15)
        {
            GB(v, v0, v4, v8, v12);
            GB(v, v1, v5, v9, v13);
            GB(v, v2, v6, v10, v14);
            GB(v, v3, v7, v11, v15);
            GB(v, v0, v5, v10, v15);
            GB(v, v1, v6, v11, v12);
            GB(v, v2, v7, v8, v13);
            GB(v, v3, v4, v9, v14);
        }

        private static void GB(ulong[] v, int a, int b, int c, int d)
        {
            v[a] = FBlaMka(v[a], v[b]); v[d] = Blake2b.RotR(v[d] ^ v[a], 32);
            v[c] = FBlaMka(v[c], v[d]); v[b] = Blake2b.RotR(v[b] ^ v[c], 24);
            v[a] = FBlaMka(v[a], v[b]); v[d] = Blake2b.RotR(v[d] ^ v[a], 16);
            v[c] = FBlaMka(v[c], v[d]); v[b] = Blake2b.RotR(v[b] ^ v[c], 63);
        }

        private static ulong FBlaMka(ulong x, ulong y) => x + y + 2 * (x & 0xFFFFFFFFUL) * (y & 0xFFFFFFFFUL);

        /// <summary>Variable-length hash H' from RFC 9106 section 3.3.</summary>
        internal static byte[] HPrime(int outLength, byte[] input)
        {
            var lenPrefix = new byte[4];
            WriteLE32(lenPrefix, 0, (uint)outLength);

            if (outLength <= 64)
                return Blake2b.Hash(outLength, lenPrefix, input);

            var output = new byte[outLength];
            int r = (outLength + 31) / 32 - 2;
            byte[] v = Blake2b.Hash(64, lenPrefix, input);
            Buffer.BlockCopy(v, 0, output, 0, 32);
            int pos = 32;
            for (int i = 1; i < r; i++)
            {
                v = Blake2b.Hash(64, v);
                Buffer.BlockCopy(v, 0, output, pos, 32);
                pos += 32;
            }
            byte[] last = Blake2b.Hash(outLength - 32 * r, v);
            Buffer.BlockCopy(last, 0, output, pos, last.Length);
            return output;
        }

        private static void LoadBlock(ulong[] mem, int offset, byte[] bytes)
        {
            for (int i = 0; i < BlockWords; i++) mem[offset + i] = Blake2b.ReadLE64(bytes, i * 8);
        }

        private static void WriteLE32(byte[] b, int o, uint v)
        {
            b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
        }
    }
}
