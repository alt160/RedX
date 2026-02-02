using System;
using System.Buffers;
using System.Security.Cryptography;

namespace RobinsonEncryptionLib
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
        }

        /// <summary>
        /// Delegate that provides entropy for automatic reseeding.
        /// </summary>
        public Func<byte[]>? ReseedCallback { get; init; }

        /// <summary>
        /// Generates pseudorandom bytes.
        /// </summary>
        private const ulong ReseedInterval = 1UL << 48;

 
        public void Generate(Span<byte> output)
        {
            if (output.Length > 8192)
                throw new ArgumentOutOfRangeException(nameof(output), "Max 8192 bytes per request");

            if ((ulong)_reseedCounter >= ReseedInterval)
            {
                if (ReseedCallback is null)
                    throw new InvalidOperationException("Reseed required and no ReseedCallback provided");

                byte[] newEntropy = ReseedCallback();
                if (newEntropy == null || newEntropy.Length == 0)
                    throw new InvalidOperationException("ReseedCallback returned no entropy");

                Reseed(newEntropy);
            }

            Span<byte> buffer = stackalloc byte[32];
            int offset = 0;

            while (offset < output.Length)
            {
                _hmac.Key = _K;
                _hmac.TryComputeHash(_V, buffer, out _);
                buffer.CopyTo(_V);

                int toCopy = Math.Min(buffer.Length, output.Length - offset);
                buffer.Slice(0, toCopy).CopyTo(output.Slice(offset, toCopy));
                offset += toCopy;
            }

            Update(ReadOnlySpan<byte>.Empty);
            _reseedCounter++;
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
        }
    }
}

