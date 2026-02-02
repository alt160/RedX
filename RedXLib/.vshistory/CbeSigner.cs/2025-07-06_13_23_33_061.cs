using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Buffers;

namespace CodeBasedSignature
{
    /// <summary>
    /// Implements a simple code-based signature encoder and verifier using a single key buffer.
    /// </summary>
    public class CbeSigner
    {
        private readonly ReadOnlyMemory<byte> _key;
        private readonly int _blockCount;
        private readonly int _blockLength;
        private const int PermBlockSize = 256;

        /// <summary>
        /// Initializes a new instance with a contiguous key buffer and signature block length.
        /// </summary>
        /// <param name="key">Secret key: N * 256 byte shuffled permutation blocks.</param>
        /// <param name="noiseLength">Bytes per signature block (e.g., 8).</param>
        public CbeSigner(ReadOnlySpan<byte> key, int noiseLength = 8)
        {
            if (key.Length % PermBlockSize != 0 || key.Length == 0)
                throw new ArgumentException("Key must be non-empty and a multiple of 256 bytes", nameof(key));
            if (noiseLength < 1)
                throw new ArgumentOutOfRangeException(nameof(noiseLength), "Block length must be at least 1.");

            _key = key.ToArray();
            _blockCount = _key.Length / PermBlockSize;
            _blockLength = noiseLength;
        }

        /// <summary>
        /// Signs the given message, producing a signature sequence of length message.Length * blockLength.
        /// </summary>
        public byte[] Sign(ReadOnlySpan<byte> message)
        {
            // Compute full-message hash
            byte[] fullHash;
            using (var sha = SHA256.Create())
                fullHash = sha.ComputeHash(message.ToArray());

            int msgLen = message.Length;
            var signature = new byte[msgLen * _blockLength];

            for (int i = 0; i < msgLen; i++)
            {
                byte plain = message[i];
                // select the permutation block
                var keySpan = _key.Slice((i % _blockCount) * PermBlockSize, PermBlockSize).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    throw new InvalidOperationException("Plain byte not found in key block");

                // derive a param from hash and key
                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_blockLength == 1 ? 1 : _blockLength - 1)) + 1;

                // write block
                var dest = signature.AsSpan(i * _blockLength, _blockLength);
                for (int j = 0; j < _blockLength; j++)
                    dest[j] = keySpan[(dIndex + j * step) & 0xFF];
            }

            return signature;
        }

        /// <summary>
        /// Verifies that the signature matches the given message.
        /// </summary>
        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != message.Length * _blockLength)
                return false;

            // Recompute full-message hash
            byte[] fullHash;
            using (var sha = SHA256.Create())
                fullHash = sha.ComputeHash(message.ToArray());

            for (int i = 0; i < message.Length; i++)
            {
                byte plain = message[i];
                var keySpan = _key.Slice((i % _blockCount) * PermBlockSize, PermBlockSize).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    return false;

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_blockLength == 1 ? 1 : _blockLength - 1)) + 1;

                var seg = signature.Slice(i * _blockLength, _blockLength);
                for (int j = 0; j < _blockLength; j++)
                    if (seg[j] != keySpan[(dIndex + j * step) & 0xFF])
                        return false;
            }

            return true;
        }

        /// <summary>
        /// Generates a single key buffer of N * 256 bytes via Fisher-Yates.
        /// </summary>
        /// <param name="blocks">Number of 256-byte permutation blocks (>=1).</param>
        public static byte[] GenerateRandomKey(int blocks)
        {
            if (blocks < 1)
                throw new ArgumentOutOfRangeException(nameof(blocks), "Must generate at least one block");

            var key = new byte[blocks * PermBlockSize];
            for (int b = 0; b < blocks; b++)
            {
                for (int i = 0; i < PermBlockSize; i++)
                    key[b * PermBlockSize + i] = (byte)i;
                for (int i = PermBlockSize - 1; i > 0; i--)
                {
                    int j = RandomNumberGenerator.GetInt32(i + 1);
                    int idx = b * PermBlockSize;
                    (key[idx + i], key[idx + j]) = (key[idx + j], key[idx + i]);
                }
            }
            return key;
        }
    }
}
