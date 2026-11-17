using System;

namespace Argon2Hashing
{
    /// <summary>
    /// Minimal BLAKE2b (RFC 7693), unkeyed, output length 1..64 bytes.
    /// Used internally by Argon2 (H0 and the variable-length hash H').
    /// </summary>
    internal sealed class Blake2b
    {
        private static readonly ulong[] IV =
        {
            0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
            0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
        };

        private static readonly byte[,] Sigma =
        {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
        };

        private readonly ulong[] _h = new ulong[8];
        private readonly ulong[] _m = new ulong[16];
        private readonly ulong[] _v = new ulong[16];
        private readonly byte[] _buffer = new byte[128];
        private int _bufferLength;
        private ulong _t0, _t1;
        private readonly int _outLength;

        public Blake2b(int outLength)
        {
            if (outLength < 1 || outLength > 64) throw new ArgumentOutOfRangeException(nameof(outLength));
            _outLength = outLength;
            Array.Copy(IV, _h, 8);
            _h[0] ^= 0x01010000UL ^ (ulong)outLength;
        }

        public void Update(byte[] data) => Update(data, 0, data.Length);

        public void Update(byte[] data, int offset, int count)
        {
            while (count > 0)
            {
                // Keep the last block in the buffer: it must be compressed with the final flag.
                if (_bufferLength == 128)
                {
                    IncrementCounter(128);
                    Compress(_buffer, 0, false);
                    _bufferLength = 0;
                }
                int take = Math.Min(128 - _bufferLength, count);
                Buffer.BlockCopy(data, offset, _buffer, _bufferLength, take);
                _bufferLength += take;
                offset += take;
                count -= take;
            }
        }

        public void UpdateLE32(uint value)
        {
            Update(new[] { (byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24) });
        }

        public byte[] Final()
        {
            IncrementCounter((ulong)_bufferLength);
            for (int i = _bufferLength; i < 128; i++) _buffer[i] = 0;
            Compress(_buffer, 0, true);

            var full = new byte[64];
            for (int i = 0; i < 8; i++) WriteLE64(full, i * 8, _h[i]);
            var result = new byte[_outLength];
            Buffer.BlockCopy(full, 0, result, 0, _outLength);
            Array.Clear(full, 0, full.Length);
            return result;
        }

        public static byte[] Hash(int outLength, params byte[][] parts)
        {
            var b = new Blake2b(outLength);
            foreach (var p in parts) b.Update(p);
            return b.Final();
        }

        private void IncrementCounter(ulong inc)
        {
            _t0 += inc;
            if (_t0 < inc) _t1++;
        }

        private void Compress(byte[] block, int offset, bool last)
        {
            for (int i = 0; i < 16; i++) _m[i] = ReadLE64(block, offset + i * 8);
            for (int i = 0; i < 8; i++) { _v[i] = _h[i]; _v[i + 8] = IV[i]; }
            _v[12] ^= _t0;
            _v[13] ^= _t1;
            if (last) _v[14] = ~_v[14];

            for (int r = 0; r < 12; r++)
            {
                G(0, 4, 8, 12, _m[Sigma[r, 0]], _m[Sigma[r, 1]]);
                G(1, 5, 9, 13, _m[Sigma[r, 2]], _m[Sigma[r, 3]]);
                G(2, 6, 10, 14, _m[Sigma[r, 4]], _m[Sigma[r, 5]]);
                G(3, 7, 11, 15, _m[Sigma[r, 6]], _m[Sigma[r, 7]]);
                G(0, 5, 10, 15, _m[Sigma[r, 8]], _m[Sigma[r, 9]]);
                G(1, 6, 11, 12, _m[Sigma[r, 10]], _m[Sigma[r, 11]]);
                G(2, 7, 8, 13, _m[Sigma[r, 12]], _m[Sigma[r, 13]]);
                G(3, 4, 9, 14, _m[Sigma[r, 14]], _m[Sigma[r, 15]]);
            }

            for (int i = 0; i < 8; i++) _h[i] ^= _v[i] ^ _v[i + 8];
        }

        private void G(int a, int b, int c, int d, ulong x, ulong y)
        {
            ulong[] v = _v;
            v[a] = v[a] + v[b] + x; v[d] = RotR(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];     v[b] = RotR(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y; v[d] = RotR(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];     v[b] = RotR(v[b] ^ v[c], 63);
        }

        internal static ulong RotR(ulong x, int n) => (x >> n) | (x << (64 - n));

        internal static ulong ReadLE64(byte[] b, int o) =>
            b[o] | ((ulong)b[o + 1] << 8) | ((ulong)b[o + 2] << 16) | ((ulong)b[o + 3] << 24) |
            ((ulong)b[o + 4] << 32) | ((ulong)b[o + 5] << 40) | ((ulong)b[o + 6] << 48) | ((ulong)b[o + 7] << 56);

        internal static void WriteLE64(byte[] b, int o, ulong v)
        {
            for (int i = 0; i < 8; i++) b[o + i] = (byte)(v >> (8 * i));
        }
    }
}
