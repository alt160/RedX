using System;
using System.Numerics;

namespace RobinsonEncryptionLib
{
    public class SimpleChameleonHash : IChameleonHash
    {
        // Public: modulus p, generator g, and h = g^a mod p
        public readonly BigInteger P, G, H;
        private readonly BigInteger _trapdoor;  // a

        // Precompute g^x for x in [0..maxIndex]
        private readonly BigInteger[] _gPow;

        public SimpleChameleonHash(BigInteger p, BigInteger g, BigInteger a, int maxIndex)
        {
            P = p; G = g; _trapdoor = a;
            H = BigInteger.ModPow(G, a, P);

            // Precompute g^x for fast discrete‐log on small domain
            _gPow = new BigInteger[maxIndex + 1];
            for (int i = 0; i <= maxIndex; i++)
                _gPow[i] = BigInteger.ModPow(G, i, P);
        }

        public byte[] PublicParam
        {
            get
            {
                // Encode (P, G, H) in some wire format
                // For simplicity: not implemented here
                throw new NotImplementedException();
            }
        }

        public byte[] Compute(int index, byte nonce)
        {
            // H_i = g^index * h^nonce mod p
            var part1 = _gPow[index];
            var part2 = BigInteger.ModPow(H, nonce, P);
            var hash = part1 * part2 % P;
            return hash.ToByteArray();  // fixed length in real code
        }

        public int Invert(byte[] H_bytes, byte nonce)
        {
            // Given H_i and nonce, solve for index:
            // g^index = H_i * (h^nonce)^(-1) mod p
            var Hi = new BigInteger(H_bytes);
            var hnInv = BigInteger.ModPow(H, nonce, P).ModInverse(P);
            var target = Hi * hnInv % P;

            // Find index such that g^index == target
            for (int i = 0; i < _gPow.Length; i++)
                if (_gPow[i] == target)
                    return i;

            throw new InvalidOperationException("Invalid CH opening");
        }
    }
}
