using Blake3;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace RedxLib
{
    /// <summary>
    /// HMAC-DRBG implementation (NIST SP 800-90A Rev.1, section 10.1.2) using HMAC-SHA256
    /// </summary>
    public class HmacDrbg : IDisposable
    {
        private readonly byte[] _K;
        private readonly byte[] _V;
        private int _reseedCounter;
        private readonly HMACSHA256 _hmac;

        private readonly byte[] _buffer = new byte[32];
        private int _bufferOffset = 32; // Start full to trigger first fill

        private const int MaxBytesPerRequest = 8192;
        private const ulong ReseedInterval = 1UL << 48;

        /// <summary>
        /// Instantiates a new HMAC-DRBG with provided entropy, optional nonce and personalization string.
        /// </summary>
        public HmacDrbg(ReadOnlySpan<byte> entropy, ReadOnlySpan<byte> nonce = default, ReadOnlySpan<byte> personalization = default)
        {
            var seedBuffer = new ArrayBufferWriter<byte>();
            seedBuffer.Write(entropy);
            if (!nonce.IsEmpty) seedBuffer.Write(nonce);
            if (!personalization.IsEmpty) seedBuffer.Write(personalization);

            _K = GC.AllocateUninitializedArray<byte>(32);
            _V = GC.AllocateUninitializedArray<byte>(32);
            Array.Fill(_K, (byte)0x00);
            Array.Fill(_V, (byte)0x01);

            _hmac = new HMACSHA256(_K);
            Update(seedBuffer.WrittenSpan);
            _reseedCounter = 1;
        }

        /// <summary>
        /// Reseeds the DRBG with new entropy.
        /// </summary>
        public void Reseed(ReadOnlySpan<byte> entropyInput)
        {
            Update(entropyInput);
            _reseedCounter = 1;
            _bufferOffset = 32;
        }

        /// <summary>
        /// Generates pseudorandom bytes.
        /// </summary>
        public void Generate(Span<byte> output)
        {
            if (output.Length > MaxBytesPerRequest)
                throw new ArgumentOutOfRangeException(nameof(output), $"Max {MaxBytesPerRequest} bytes per request");

            if ((ulong)_reseedCounter >= ReseedInterval)
                throw new InvalidOperationException("Reseed required: reseed interval exceeded");

            int offset = 0;

            while (offset < output.Length)
            {
                if (_bufferOffset >= 32)
                {
                    _hmac.Key = _K;
                    _hmac.TryComputeHash(_V, _buffer, out _);
                    Buffer.BlockCopy(_buffer, 0, _V, 0, 32);
                    _bufferOffset = 0;
                }

                int toCopy = Math.Min(32 - _bufferOffset, output.Length - offset);
                new Span<byte>(_buffer, _bufferOffset, toCopy).CopyTo(output.Slice(offset, toCopy));
                _bufferOffset += toCopy;
                offset += toCopy;
            }

            Update(ReadOnlySpan<byte>.Empty);
            _reseedCounter++;
        }

        /// <summary>
        /// Generates pseudorandom shorts.
        /// </summary>
        public void Generate(Span<short> output)
        {
            Span<byte> temp = stackalloc byte[output.Length * sizeof(short)];
            Generate(temp);
            MemoryMarshal.Cast<byte, short>(temp).CopyTo(output);
        }

        /// <summary>
        /// Generates pseudorandom ints.
        /// </summary>
        public void Generate(Span<int> output)
        {
            Span<byte> temp = stackalloc byte[output.Length * sizeof(int)];
            Generate(temp);
            MemoryMarshal.Cast<byte, int>(temp).CopyTo(output);
        }


        private void Update(ReadOnlySpan<byte> providedData)
        {
            Span<byte> tempInput = stackalloc byte[_V.Length + 1 + providedData.Length];
            _V.CopyTo(tempInput);
            tempInput[_V.Length] = 0x00;
            providedData.CopyTo(tempInput.Slice(_V.Length + 1));

            _hmac.Key = _K;
            Span<byte> kResult = stackalloc byte[32];
            _hmac.TryComputeHash(tempInput, kResult, out _);
            kResult.CopyTo(_K);

            _hmac.Key = _K;
            Span<byte> vResult = stackalloc byte[32];
            _hmac.TryComputeHash(_V, vResult, out _);
            vResult.CopyTo(_V);

            if (providedData.Length > 0)
            {
                tempInput[_V.Length] = 0x01;
                providedData.CopyTo(tempInput.Slice(_V.Length + 1));

                _hmac.Key = _K;
                _hmac.TryComputeHash(tempInput, kResult, out _);
                kResult.CopyTo(_K);

                _hmac.Key = _K;
                _hmac.TryComputeHash(_V, vResult, out _);
                vResult.CopyTo(_V);
            }
        }

        public void Dispose()
        {
            _hmac?.Dispose();
            CryptographicOperations.ZeroMemory(_K);
            CryptographicOperations.ZeroMemory(_V);
            CryptographicOperations.ZeroMemory(_buffer);
        }
    }

    internal static class BufferWriterExtensions
    {
        public static void Write(this IBufferWriter<byte> writer, ReadOnlySpan<byte> span)
        {
            var memory = writer.GetSpan(span.Length);
            span.CopyTo(memory);
            writer.Advance(span.Length);
        }
    }
}
