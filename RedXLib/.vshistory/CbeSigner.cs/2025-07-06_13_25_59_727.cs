using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Buffers;

namespace CodeBasedSignature
{
    /// <summary>
    /// Implements a simple code-based signature encoder and verifier using a single key buffer,
    /// with optional sliding-XOR folding to reduce signature size.
    /// </summary>
    public class CbeSigner
    {
        private readonly ReadOnlyMemory<byte> _key;
        private readonly int _blockCount;
        private readonly int _noiseLength;
        private const int PermBlockSize = 256;

        /// <summary>
        /// Initializes a new instance with a contiguous key buffer and noise length per byte.
        /// </summary>
        /// <param name="key">Secret key: N * 256-byte shuffled permutation blocks.</param>
        /// <param name="noiseLength">Number of noise bytes per message byte (>=1).</param>
        public CbeSigner(ReadOnlySpan<byte> key, int noiseLength)
        {
            if (key.Length % PermBlockSize != 0 || key.Length == 0)
                throw new ArgumentException("Key must be non-empty and a multiple of 256 bytes", nameof(key));
            if (noiseLength < 1)
                throw new ArgumentOutOfRangeException(nameof(noiseLength), "Noise length must be at least 1.");

            _key = key.ToArray();
            _blockCount = _key.Length / PermBlockSize;
            _noiseLength = noiseLength;
        }

        /// <summary>
        /// Produces the raw signature: message.Length * noiseLength bytes.
        /// </summary>
        public byte[] SignRaw(ReadOnlySpan<byte> message)
        {
            var fullHash = SHA256.Create().ComputeHash(message.ToArray());
            int msgLen = message.Length;
            var signature = new byte[msgLen * _noiseLength];

            for (int i = 0; i < msgLen; i++)
            {
                byte plain = message[i];
                var keySpan = _key.Slice((i % _blockCount) * PermBlockSize, PermBlockSize).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    throw new InvalidOperationException("Plain byte not found in key block");

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_noiseLength == 1 ? 1 : _noiseLength - 1)) + 1;

                var dest = signature.AsSpan(i * _noiseLength, _noiseLength);
                for (int j = 0; j < _noiseLength; j++)
                    dest[j] = keySpan[(dIndex + j * step) & 0xFF];
            }

            return signature;
        }

        /// <summary>
        /// Verifies a raw signature against the message.
        /// </summary>
        public bool VerifyRaw(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != message.Length * _noiseLength)
                return false;

            var fullHash = SHA256.Create().ComputeHash(message.ToArray());
            int msgLen = message.Length;

            for (int i = 0; i < msgLen; i++)
            {
                byte plain = message[i];
                var keySpan = _key.Slice((i % _blockCount) * PermBlockSize, PermBlockSize).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    return false;

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_noiseLength == 1 ? 1 : _noiseLength - 1)) + 1;

                var seg = signature.Slice(i * _noiseLength, _noiseLength);
                for (int j = 0; j < _noiseLength; j++)
                    if (seg[j] != keySpan[(dIndex + j * step) & 0xFF])
                        return false;
            }
            return true;
        }

        /// <summary>
        /// Folds a raw signature into a smaller buffer using sliding-XOR overlay.
        /// Result length = messageLength + noiseLength - 1.
        /// </summary>
        public byte[] FoldSignature(ReadOnlySpan<byte> rawSignature, int messageLength)
        {
            int foldedLen = messageLength + _noiseLength - 1;
            var folded = new byte[foldedLen];
            for (int i = 0; i < messageLength; i++)
            {
                var block = rawSignature.Slice(i * _noiseLength, _noiseLength);
                for (int j = 0; j < _noiseLength; j++)
                    folded[i + j] ^= block[j];
            }
            return folded;
        }

        /// <summary>
        /// Unfolds a folded signature back into raw form for verification.
        /// </summary>
        public byte[] UnfoldSignature(ReadOnlySpan<byte> folded, int messageLength)
        {
            var raw = new byte[messageLength * _noiseLength];
            // recover last block directly
            int lastIndex = messageLength - 1;
            for (int j = 0; j < _noiseLength; j++)
                raw[lastIndex * _noiseLength + j] = folded[lastIndex + j];
            // peel off earlier blocks backwards
            for (int i = messageLength - 2; i >= 0; i--)
            {
                for (int j = 0; j < _noiseLength; j++)
                    raw[i * _noiseLength + j] = (byte)(folded[i + j] ^ raw[(i + 1) * _noiseLength + j]);
            }
            return raw;
        }

        /// <summary>
        /// Generates a single key buffer of N * 256 bytes via Fisher-Yates.
        /// </summary>
        public static byte[] GenerateRandomKey(int blocks)
        {
            if (blocks < 1)
                throw new ArgumentOutOfRangeException(nameof(blocks), "Must generate at least one block");
            var key = new byte[blocks * PermBlockSize];
            for (int b = 0; b < blocks; b++)
            {
                for (int i = 0; i < PermBlockSize; i++) key[b * PermBlockSize + i] = (byte)i;
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
