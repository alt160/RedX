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
    /// var signer = new CbeSigner(key, blockLength: 8);
    /// byte[] msg = System.Text.Encoding.UTF8.GetBytes("hello");
    /// byte[] signature = signer.Sign(msg);
    /// bool valid = signer.Verify(msg, signature);
    /// </code>
    /// </example>
    public class CbeSigner
    {
        private readonly ReadOnlyMemory<byte> _key;
        private readonly int _blockLength;
        private readonly int _blockCount;

        /// <summary>
        /// Initializes a new instance with a contiguous key buffer.
        /// </summary>
        /// <param name="key">Secret key: N * 256 byte shuffled permutation blocks.</param>
        /// <param name="blockLength">Bytes per encoded block (2..256).</param>
        public CbeSigner(ReadOnlySpan<byte> key, int blockLength)
        {
            if (key.Length % 256 != 0 || key.Length == 0)
                throw new ArgumentException("Key must be non-empty and a multiple of 256 bytes", nameof(key));
            if (blockLength < 2 || blockLength > 256)
                throw new ArgumentOutOfRangeException(nameof(blockLength), "Block length must be between 2 and 256.");

            _key = key.ToArray();
            _blockLength = blockLength;
            _blockCount = _key.Length / 256;
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
            var signature = new byte[msgLen * _blockLength];

            for (int i = 0; i < msgLen; i++)
            {
                byte plain = message[i];
                // determine block segment
                ReadOnlySpan<byte> keySpan = _key.Slice((i % _blockCount) * 256, 256).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    throw new InvalidOperationException("Plain byte not found in key block");

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_blockLength - 1)) + 1;

                var dest = signature.AsSpan(i * _blockLength, _blockLength);
                if (_blockLength == sizeof(ulong))
                {
                    Span<ulong> destUlong = MemoryMarshal.Cast<byte, ulong>(dest);
                    ulong packed = 0;
                    for (int j = 0; j < _blockLength; j++)
                        packed |= (ulong)keySpan[(dIndex + j * step) & 0xFF] << (8 * j);
                    destUlong[0] = packed;
                }
                else
                {
                    for (int j = 0; j < _blockLength; j++)
                        dest[j] = keySpan[(dIndex + j * step) & 0xFF];
                }
            }

            return signature;
        }

        /// <summary>
        /// Verifies that signature matches message.
        /// </summary>
        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != message.Length * _blockLength)
                return false;

            byte[] fullHash;
            using (var sha = SHA256.Create())
                fullHash = sha.ComputeHash(message.ToArray());

            for (int i = 0; i < message.Length; i++)
            {
                byte plain = message[i];
                ReadOnlySpan<byte> keySpan = _key.Slice((i % _blockCount) * 256, 256).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0) return false;

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_blockLength - 1)) + 1;

                var seg = signature.Slice(i * _blockLength, _blockLength);
                if (_blockLength == sizeof(ulong))
                {
                    ulong expected = MemoryMarshal.Cast<byte, ulong>(seg)[0];
                    ulong packed = 0;
                    for (int j = 0; j < _blockLength; j++)
                        packed |= (ulong)keySpan[(dIndex + j * step) & 0xFF] << (8 * j);
                    if (packed != expected) return false;
                }
                else
                {
                    for (int j = 0; j < _blockLength; j++)
                        if (seg[j] != keySpan[(dIndex + j * step) & 0xFF])
                            return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Generates a single key buffer of N * 256 bytes.
        /// </summary>
        public static byte[] GenerateRandomKey(int blocks)
        {
            if (blocks < 2)
                throw new ArgumentOutOfRangeException(nameof(blocks));
            var key = new byte[blocks * 256];
            for (int b = 0; b < blocks; b++)
            {
                // initialize
                for (int i = 0; i < 256; i++) key[b * 256 + i] = (byte)i;
                // Fisher-Yates
                for (int i = 255; i > 0; i--)
                {
                    int j = RandomNumberGenerator.GetInt32(i + 1);
                    int idx = b * 256;
                    (key[idx + i], key[idx + j]) = (key[idx + j], key[idx + i]);
                }
            }
            return key;
        }
    }
}
