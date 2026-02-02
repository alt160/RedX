using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RobinsonEncryptionLib
{
    public class SmallPrimeChameleon : IChameleonHash
    {
        // A 32-bit prime and generator
        private const uint P = 0xFFFF_FEB3;   // e.g. 4 294 901 235 (just under 2^32)
        private const uint G = 3;
        private readonly uint _h;            // = G^a mod P
        private readonly uint _a;            // trapdoor in [0..P)
        private readonly uint[] _gPow;

        public SmallPrimeChameleon(uint trapdoorA, int maxIndex)
        {
            _a = trapdoorA;
            _h = ModPow(G, _a, P);
            // Precompute g^x for x=0..maxIndex
            _gPow = new uint[maxIndex + 1];
            for (int x = 0; x <= maxIndex; x++)
                _gPow[x] = ModPow(G, (uint)x, P);

        }

        public byte[] PublicParam => BitConverter.GetBytes(_h);

        public byte[] Compute(int x, ushort r)
        {
            var buf = new byte[4];
            Compute(x, r, buf);
            return buf;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Compute(int x, ushort r, Span<byte> result)
        {
            if (result.Length < 4)
                 throw new ArgumentException("result must be at least 4 bytes.");

            // 1) gx = g^x mod p
            uint gx = ModPow(G, (uint)x, P);

            // 2) hr = h^r mod p
            uint hr = ModPow(_h, r, P);

            // 3) H = (gx * hr) mod p
            uint H = (uint)((ulong)gx * hr % P);

            // 4) write H little-endian into the provided span
            MemoryMarshal.Write(result, ref H);
        }


        public int Invert(Span<byte> H_bytes, ushort r)
        {
            if(H_bytes.Length < 4) throw new ArgumentException("H_bytes must be 4 at least bytes.");
            uint Hval = MemoryMarshal.Read<uint>(H_bytes);
            // compute inverse of h^r mod P via Fermat
            uint hr = ModPow(_h, r, P);
            uint hrInv = ModPow(hr, P - 2, P);  // since P is prime

            // target = g^x = H * hrInv mod P
            uint target = (uint)((ulong)Hval * hrInv % P);

            // brute-find x in [0..255] (or your maxIndex)
            for (int x = 0; x < _gPow.Length; x++)
                if (_gPow[x] == target)
                    return x;

            throw new InvalidOperationException("Invalid opening");
        }

        // fast modular exponentiation in 64-bit
        private static uint ModPow(uint @base, uint exp, uint mod)
        {
            ulong result = 1, b = @base;
            while (exp > 0)
            {
                if ((exp & 1) != 0) result = (result * b) % mod;
                b = (b * b) % mod;
                exp >>= 1;
            }
            return (uint)result;
        }
    }

}
