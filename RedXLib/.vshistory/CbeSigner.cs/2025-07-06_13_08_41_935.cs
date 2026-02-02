using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Buffers;

namespace CodeBasedSignature
{
    /// <summary>
    /// Implements a simple code-based signature encoder and verifier.
    /// </summary>
    /// <remarks>
    /// <example>
    /// <code>
    /// var keyBlocks = CbeSigner.GenerateRandomKeyBlocks(2);
    /// var signer = new CbeSigner(keyBlocks, blockLength: 8);
    /// byte[] msg = System.Text.Encoding.UTF8.GetBytes("hello");
    /// byte[] signature = signer.Sign(msg);
    /// bool valid = signer.Verify(msg, signature);
    /// </code>
    /// </example>
    /// <seealso href="https://docs.microsoft.com/dotnet/api/system.span-1" />
    /// <seealso href="https://docs.microsoft.com/dotnet/api/system.runtime.interopservices.memorymarshal" />
    public class CbeSigner
    {
        private readonly ReadOnlyMemory<byte>[] _keyBlocks;
        private readonly int _blockLength;

        public CbeSigner(ReadOnlyMemory<byte>[] keyBlocks, int blockLength)
        {
            if (keyBlocks == null || keyBlocks.Length == 0)
                throw new ArgumentException("Must supply at least one 256-byte block", nameof(keyBlocks));
            foreach (var km in keyBlocks)
                if (km.Length != 256)
                    throw new ArgumentException("Each key block must be exactly 256 bytes", nameof(keyBlocks));
            if (blockLength < 1 || blockLength > 256)
                throw new ArgumentOutOfRangeException(nameof(blockLength));

            _keyBlocks = keyBlocks;
            _blockLength = blockLength;
        }

        /// <summary>
        /// Signs the given message, producing a signature byte sequence.
        /// </summary>
        public byte[] Sign(ReadOnlySpan<byte> message)
        {
            // Full-message hash
            byte[] fullHash;
            using (var sha = SHA256.Create())
                fullHash = sha.ComputeHash(message.ToArray());

            int msgLen = message.Length;
            var signature = new byte[msgLen * _blockLength];

            for (int i = 0; i < msgLen; i++)
            {
                byte plain = message[i];
                var keySpan = _keyBlocks[i % _keyBlocks.Length].Span;
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
        /// Verifies the signature matches the given message.
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
                var keySpan = _keyBlocks[i % _keyBlocks.Length].Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    return false;

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_blockLength - 1)) + 1;

                var sigSegment = signature.Slice(i * _blockLength, _blockLength);
                if (_blockLength == sizeof(ulong))
                {
                    var segUlong = MemoryMarshal.Cast<byte, ulong>(sigSegment);
                    ulong expected = segUlong[0];
                    ulong packed = 0;
                    for (int j = 0; j < _blockLength; j++)
                        packed |= (ulong)keySpan[(dIndex + j * step) & 0xFF] << (8 * j);
                    if (packed != expected)
                        return false;
                }
                else
                {
                    for (int j = 0; j < _blockLength; j++)
                        if (sigSegment[j] != keySpan[(dIndex + j * step) & 0xFF])
                            return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Generates random 256-byte key blocks via Fisher-Yates shuffle.
        /// </summary>
        public static ReadOnlyMemory<byte>[] GenerateRandomKeyBlocks(int count)
        {
            if (count < 1)
                throw new ArgumentOutOfRangeException(nameof(count), "Must generate at least one block");

            var blocks = new ReadOnlyMemory<byte>[count];
            for (int b = 0; b < count; b++)
            {
                var arr = new byte[256];
                for (int i = 0; i < 256; i++)
                    arr[i] = (byte)i;
                for (int i = 255; i > 0; i--)
                {
                    int j = RandomNumberGenerator.GetInt32(i + 1);
                    (arr[i], arr[j]) = (arr[j], arr[i]);
                }
                blocks[b] = arr;
            }
            return blocks;
        }
    }
}
