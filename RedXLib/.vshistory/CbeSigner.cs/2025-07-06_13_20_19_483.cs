using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Buffers;

namespace CodeBasedSignature
{
    /// <summary>
    /// Implements a simple code-based signature encoder and verifier using a single key buffer.
    /// </summary>
    /// <remarks>
    /// <example>
    /// <code>
    /// // Key must be a multiple of 256 bytes
    /// byte[] key = CbeSigner.GenerateRandomKey(2); // 2 blocks = 512 bytes
    /// var signer = new CbeSigner(key);
    /// byte[] msg = System.Text.Encoding.UTF8.GetBytes("hello");
    /// byte[] signature = signer.Sign(msg);
    /// bool valid = signer.Verify(msg, signature);
    /// </code>
    /// </example>
    public class CbeSigner
    {
        private readonly ReadOnlyMemory<byte> _key;
        private readonly int _blockCount;
        private const int BlockLength = 256;

        /// <summary>
        /// Initializes a new instance with a contiguous key buffer.
        /// </summary>
        /// <param name="key">Secret key: N * 256 byte shuffled permutation blocks.</param>
        public CbeSigner(ReadOnlySpan<byte> key)
        {
            if (key.Length % BlockLength != 0 || key.Length == 0)
                throw new ArgumentException("Key must be non-empty and a multiple of 256 bytes", nameof(key));

            _blockCount = key.Length / BlockLength;
            _key = key.ToArray();
        }

        /// <summary>
        /// Signs the given message.
        /// </summary>
        public byte[] Sign(ReadOnlySpan<byte> message)
        {
            byte[] fullHash;
            using (var sha = SHA256.Create())
                fullHash = sha.ComputeHash(message.ToArray());

            int msgLen = message.Length;
            var signature = new byte[msgLen * BlockLength];

            for (int i = 0; i < msgLen; i++)
            {
                byte plain = message[i];
                var keySpan = _key.Slice((i % _blockCount) * BlockLength, BlockLength).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    throw new InvalidOperationException("Plain byte not found in key block");

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (BlockLength - 1)) + 1;

                var dest = signature.AsSpan(i * BlockLength, BlockLength);
                // pack 256-byte block: fallback to byte-by-byte
                for (int j = 0; j < BlockLength; j++)
                    dest[j] = keySpan[(dIndex + j * step) & 0xFF];
            }

            return signature;
        }

        /// <summary>
        /// Verifies that signature matches message.
        /// </summary>
        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != message.Length * BlockLength)
                return false;

            byte[] fullHash;
            using (var sha = SHA256.Create())
                fullHash = sha.ComputeHash(message.ToArray());

            for (int i = 0; i < message.Length; i++)
            {
                byte plain = message[i];
                var keySpan = _key.Slice((i % _blockCount) * BlockLength, BlockLength).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    return false;

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (BlockLength - 1)) + 1;

                var seg = signature.Slice(i * BlockLength, BlockLength);
                for (int j = 0; j < BlockLength; j++)
                    if (seg[j] != keySpan[(dIndex + j * step) & 0xFF])
                        return false;
            }
            return true;
        }

        /// <summary>
        /// Generates a single key buffer of N * 256 bytes.
        /// </summary>
        /// <param name="blocks">Number of 256-byte permutation blocks to generate (>=1).</param>
        public static byte[] GenerateRandomKey(int blocks)
        {
            if (blocks < 1)
                throw new ArgumentOutOfRangeException(nameof(blocks), "Must generate at least one block");

            var key = new byte[blocks * BlockLength];
            for (int b = 0; b < blocks; b++)
            {
                // initialize
                for (int i = 0; i < BlockLength; i++) key[b * BlockLength + i] = (byte)i;
                // Fisher-Yates shuffle
                for (int i = BlockLength - 1; i > 0; i--)
                {
                    int j = RandomNumberGenerator.GetInt32(i + 1);
                    int idx = b * BlockLength;
                    (key[idx + i], key[idx + j]) = (key[idx + j], key[idx + i]);
                }
            }
            return key;
        }
    }
}
