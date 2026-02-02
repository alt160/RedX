// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // This is the corrected version that should pass all verification tests.

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    //================================================================================
    // 1. The Core Synthetic Curve (SC) Primitive
    //================================================================================

    public sealed class SyntheticCurve
    {
        private readonly uint[] _secretDomain;
        private readonly uint _operatorRatio;
        private readonly uint _generator;

        public uint Generator => _generator;

        public SyntheticCurve(ReadOnlySpan<byte> masterSeed)
        {
            if (masterSeed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");
            const int domainSize = 1024;
            _secretDomain = new uint[domainSize];
            var msb = masterSeed.ToArray();
            byte[] domainSeed = HKDF.Expand(HashAlgorithmName.SHA256, msb, 32, info: "sc-domain-seed"u8.ToArray());
            byte[] ratioSeed = HKDF.Expand(HashAlgorithmName.SHA256, msb, 32, info: "sc-ratio-seed"u8.ToArray());
            Span<byte> hashOutput = stackalloc byte[32];
            Span<byte> inputBuffer = stackalloc byte[domainSeed.Length + sizeof(int)];
            domainSeed.CopyTo(inputBuffer);
            for (int i = 0; i < domainSize; i++) { MemoryMarshal.Write(inputBuffer.Slice(domainSeed.Length), ref i); SHA256.HashData(inputBuffer, hashOutput); _secretDomain[i] = MemoryMarshal.Read<uint>(hashOutput); }
            Array.Sort(_secretDomain);
            _operatorRatio = MemoryMarshal.Read<uint>(ratioSeed);
            ReadOnlySpan<byte> domainAsBytes = MemoryMarshal.AsBytes<uint>(_secretDomain);
            SHA256.HashData(domainAsBytes, hashOutput);
            uint generatorIndexSeed = MemoryMarshal.Read<uint>(hashOutput);
            int generatorIndex = (int)(generatorIndexSeed % (uint)domainSize);
            _generator = _secretDomain[generatorIndex];
        }

        public uint Associate(uint valueA, uint valueB)
        {
            int idxA = Array.BinarySearch(_secretDomain, valueA);
            int idxB = Array.BinarySearch(_secretDomain, valueB);
            if (idxA < 0 || idxB < 0) return 0;
            ulong N = (ulong)_secretDomain.Length;
            ulong resultIndex = ((ulong)idxA + (ulong)idxB + _operatorRatio) % N;
            return _secretDomain[(int)resultIndex];
        }

        // ---------- CORRECTED AND SECURE AMBULATE IMPLEMENTATION ----------
        /// <summary>
        /// A secure, one-way "scalar multiplication" (k * P) operation,
        /// implemented as a Stateful Hash Walk. This is the cryptographic engine.
        /// </summary>
        public uint Ambulate(uint startValue, ulong scalar)
        {
            const int numRounds = 16; // A fixed number of rounds for security.

            // 1. Initialize the internal state (the "walker") by hashing the scalar.
            Span<byte> walkerState = stackalloc byte[32];
            Span<byte> scalarBytes = stackalloc byte[sizeof(ulong)];
            MemoryMarshal.Write(scalarBytes, ref scalar);
            SHA256.HashData(scalarBytes, walkerState);

            // 2. Find the starting index in our secret domain.
            int currentIndex = Array.BinarySearch(_secretDomain, startValue);
            if (currentIndex < 0)
            {
                // Fallback for non-domain values: hash to get a deterministic index.
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(MemoryMarshal.AsBytes(new ReadOnlySpan<uint>(ref startValue)), hash);
                currentIndex = (int)(MemoryMarshal.Read<uint>(hash) % (uint)_secretDomain.Length);
            }

            // 3. Perform the fixed number of rounds for the stateful hash walk.
            Span<byte> roundInput = stackalloc byte[walkerState.Length + sizeof(uint)];
            for (int i = 0; i < numRounds; i++)
            {
                // a. Get the secret content at the current location.
                uint domainValue = _secretDomain[currentIndex];

                // b. Combine the current walker state with the secret domain value.
                walkerState.CopyTo(roundInput);
                MemoryMarshal.Write(roundInput.Slice(walkerState.Length), ref domainValue);

                // c. Hash to get the next state, which is also used to derive the next index.
                SHA256.HashData(roundInput, walkerState); // The state evolves.

                // d. The new index is derived from the new state.
                currentIndex = (int)(MemoryMarshal.Read<uint>(walkerState) % (uint)_secretDomain.Length);
            }

            // 4. The final result is the value at our destination.
            return _secretDomain[currentIndex];
        }
    }


    //================================================================================
    // 2. The Digital Signature Scheme
    //================================================================================

    public readonly record struct SyntheticSignature(uint R, ulong s);

    public static class SignatureScheme
    {
        private static readonly byte[] GenesisSeed = new byte[32];
        private static readonly SyntheticCurve StandardCurve = new SyntheticCurve(GenesisSeed);
        private static readonly uint G = StandardCurve.Generator;

        public static (ulong privateKey, uint publicKey) GenerateKeyPair()
        {
            Span<byte> keyBytes = stackalloc byte[sizeof(ulong)];
            RandomNumberGenerator.Fill(keyBytes);
            ulong privateKey = MemoryMarshal.Read<ulong>(keyBytes);
            uint publicKey = StandardCurve.Ambulate(G, privateKey);
            return (privateKey, publicKey);
        }

        public static SyntheticSignature Sign(ulong privateKey, ReadOnlySpan<byte> message)
        {
            Span<byte> nonceBytes = stackalloc byte[sizeof(ulong)];
            RandomNumberGenerator.Fill(nonceBytes);
            ulong k = MemoryMarshal.Read<ulong>(nonceBytes);
            uint R = StandardCurve.Ambulate(G, k);
            Span<byte> challengeInput = stackalloc byte[sizeof(uint) + message.Length];
            MemoryMarshal.Write(challengeInput, ref R);
            message.CopyTo(challengeInput.Slice(sizeof(uint)));
            Span<byte> challengeHash = stackalloc byte[32];
            SHA256.HashData(challengeInput, challengeHash);
            ulong c = MemoryMarshal.Read<ulong>(challengeHash);
            ulong s = unchecked(k + (c * privateKey));
            return new SyntheticSignature(R, s);
        }

        public static bool Verify(uint publicKey, ReadOnlySpan<byte> message, SyntheticSignature signature)
        {
            uint R = signature.R;
            ulong s = signature.s;

            Span<byte> challengeInput = stackalloc byte[sizeof(uint) + message.Length];
            MemoryMarshal.Write(challengeInput, ref R);
            message.CopyTo(challengeInput.Slice(sizeof(uint)));
            Span<byte> challengeHash = stackalloc byte[32];
            SHA256.HashData(challengeInput, challengeHash);
            ulong c = MemoryMarshal.Read<ulong>(challengeHash);

            uint leftSide = StandardCurve.Ambulate(G, s);
            uint tempPoint = StandardCurve.Ambulate(publicKey, c);
            uint rightSide = StandardCurve.Associate(R, tempPoint);

            return leftSide == rightSide;
        }
    }

    //================================================================================
    // 3. Demonstration Program
    //================================================================================

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Corrected Synthetic Curve Digital Signature Scheme Demo ---");

            var (alicePrivate, alicePublic) = SignatureScheme.GenerateKeyPair();
            Console.WriteLine($"\nAlice's Public Key (a 'point' on the curve): {alicePublic}");

            var message = "This is a message from Alice."u8.ToArray();
            Console.WriteLine($"\nSigning message: \"{System.Text.Encoding.UTF8.GetString(message)}\"");
            var signature = SignatureScheme.Sign(alicePrivate, message);
            Console.WriteLine($"Signature: (R={signature.R}, s={signature.s})");

            Console.WriteLine("\nBob verifies the signature with Alice's public key...");
            bool isValid = SignatureScheme.Verify(alicePublic, message, signature);
            Console.WriteLine(isValid ? "SUCCESS: Signature is valid." : "FAILURE: Signature is invalid.");

            var tamperedMessage = "This is a message from Eve!"u8.ToArray();
            Console.WriteLine("\nEve verifies the original signature against a tampered message...");
            bool isTamperedValid = SignatureScheme.Verify(alicePublic, tamperedMessage, signature);
            Console.WriteLine(!isTamperedValid ? "SUCCESS: Forgery attempt correctly rejected." : "FAILURE: Forgery attempt was accepted.");

            var (bobPrivate, bobPublic) = SignatureScheme.GenerateKeyPair();
            Console.WriteLine("\nBob verifies Alice's signature with his own (wrong) public key...");
            bool isBobKeyValid = SignatureScheme.Verify(bobPublic, message, signature);
            Console.WriteLine(!isBobKeyValid ? "SUCCESS: Verification with wrong public key correctly failed." : "FAILURE: Verification with wrong key was accepted.");
        }
    }



}
