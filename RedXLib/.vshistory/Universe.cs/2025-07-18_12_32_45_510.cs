// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SCSignatureDemo
    //          cd SCSignatureDemo
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    //================================================================================
    // 1. The Core Synthetic Curve (SC) Primitive
    //================================================================================

    /// <summary>
    /// A primitive that defines a "Synthetic Curve" with a secret, generative structure.
    /// In this public-key model, the SC is instantiated with a standard, PUBLIC seed,
    /// making its behavior consistent for all users.
    /// </summary>
    public sealed class SyntheticCurve
    {
        private readonly uint[] _secretDomain;
        private readonly uint _operatorRatio;
        private readonly uint _generator;

        /// <summary>
        /// The public, deterministic starting point ("Generator Point") for this curve.
        /// </summary>
        public uint Generator => _generator;

        /// <summary>
        /// Creates a Synthetic Curve instance from a master seed.
        /// </summary>
        public SyntheticCurve(ReadOnlySpan<byte> masterSeed)
        {
            if (masterSeed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");

            var msb = masterSeed.ToArray();
            // Use a KDF to derive separate, independent seeds for each component from the master seed.
            byte[] domainSeed = HKDF.Expand(HashAlgorithmName.SHA256, msb, 32, info: "sc-domain-seed"u8.ToArray());
            byte[] ratioSeed = HKDF.Expand(HashAlgorithmName.SHA256, msb, 32, info: "sc-ratio-seed"u8.ToArray());

            // For this toy model, the domain size is fixed.
            const int domainSize = 1024;
            _secretDomain = new uint[domainSize];

            // Populate the domain using the derived domainSeed.
            Span<byte> hashOutput = stackalloc byte[32];
            Span<byte> inputBuffer = stackalloc byte[domainSeed.Length + sizeof(int)];
            domainSeed.CopyTo(inputBuffer);
            for (int i = 0; i < domainSize; i++)
            {
                MemoryMarshal.Write(inputBuffer.Slice(domainSeed.Length), ref i);
                SHA256.HashData(inputBuffer, hashOutput);
                _secretDomain[i] = MemoryMarshal.Read<uint>(hashOutput);
            }
            Array.Sort(_secretDomain);

            // The "ratio" (operator parameter) is derived from the ratioSeed.
            _operatorRatio = MemoryMarshal.Read<uint>(ratioSeed);

            // Holistically derive the generator from the final domain content.
            ReadOnlySpan<byte> domainAsBytes = MemoryMarshal.AsBytes<uint>(_secretDomain);
            SHA256.HashData(domainAsBytes, hashOutput);
            uint generatorIndexSeed = MemoryMarshal.Read<uint>(hashOutput);
            int generatorIndex = (int)(generatorIndexSeed % (uint)domainSize);
            _generator = _secretDomain[generatorIndex];
        }

        /// <summary>
        /// The associative "point addition" operation (P + Q).
        /// Its behavior is parameterized by the curve's secret ratio.
        /// </summary>
        public uint Associate(uint valueA, uint valueB)
        {
            int idxA = Array.BinarySearch(_secretDomain, valueA);
            int idxB = Array.BinarySearch(_secretDomain, valueB);

            // In a real system, you would handle this error more gracefully.
            if (idxA < 0 || idxB < 0) return 0;

            ulong N = (ulong)_secretDomain.Length;
            // The operation's result is influenced by the secret _operatorRatio.
            ulong resultIndex = ((ulong)idxA + (ulong)idxB + _operatorRatio) % N;

            return _secretDomain[(int)resultIndex];
        }

        /// <summary>
        /// The one-way "scalar multiplication" operation (k * P).
        /// </summary>
        public uint Ambulate(uint startValue, ulong scalar) // Changed to ulong for larger key space
        {
            // For this toy, the scalar determines the number of "doubling" steps.
            // A real system would use a more robust, constant-time bitwise method.
            uint numSteps = (uint)(scalar % 8) + 8; // e.g., 8 to 15 steps.

            uint currentValue = startValue;
            for (int i = 0; i < numSteps; i++)
            {
                // The core operation is P = P + P, which is Associate(P, P).
                currentValue = Associate(currentValue, currentValue);
            }
            return currentValue;
        }
    }


    //================================================================================
    // 2. The Digital Signature Scheme
    //================================================================================

    // A simple structure to hold the two parts of our signature.
    public readonly record struct SyntheticSignature(uint R, ulong s);

    public static class SignatureScheme
    {
        // A PUBLIC, standard seed that defines our curve for everyone.
        // In a real system, this would be a well-known, published constant.
        private static readonly byte[] GenesisSeed = new byte[32]; // All zeros for this demo.

        // Everyone uses the same instance of the curve, created from the public seed.
        private static readonly SyntheticCurve StandardCurve = new SyntheticCurve(GenesisSeed);
        private static readonly uint G = StandardCurve.Generator;

        public static (ulong privateKey, uint publicKey) GenerateKeyPair()
        {
            // A user's private key is a large random scalar.
            Span<byte> keyBytes = stackalloc byte[sizeof(ulong)];
            RandomNumberGenerator.Fill(keyBytes);
            ulong privateKey = MemoryMarshal.Read<ulong>(keyBytes);

            // The public key is a "point" on the standard curve, derived from the private key.
            uint publicKey = StandardCurve.Ambulate(G, privateKey);

            return (privateKey, publicKey);
        }

        public static SyntheticSignature Sign(ulong privateKey, ReadOnlySpan<byte> message)
        {
            // 1. Generate a random, one-time secret nonce 'k'. This is critical for security.
            Span<byte> nonceBytes = stackalloc byte[sizeof(ulong)];
            RandomNumberGenerator.Fill(nonceBytes);
            ulong k = MemoryMarshal.Read<ulong>(nonceBytes);

            // 2. Commitment: R = k*G
            uint R = StandardCurve.Ambulate(G, k);

            // 3. Challenge: c = H(R || M). The signature depends on the message content.
            Span<byte> challengeInput = stackalloc byte[sizeof(uint) + message.Length];
            MemoryMarshal.Write(challengeInput, ref R);
            message.CopyTo(challengeInput.Slice(sizeof(uint)));
            Span<byte> challengeHash = stackalloc byte[32];
            SHA256.HashData(challengeInput, challengeHash);
            ulong c = MemoryMarshal.Read<ulong>(challengeHash);

            // 4. Response: s = k + c * privateKey.
            // We use 'unchecked' for this toy modular arithmetic. A real system would use a large prime modulus.
            ulong s = unchecked(k + (c * privateKey));

            return new SyntheticSignature(R, s);
        }

        public static bool Verify(uint publicKey, ReadOnlySpan<byte> message, SyntheticSignature signature)
        {
            uint R = signature.R;
            ulong s = signature.s;

            // 1. Recreate the challenge hash 'c' from public information.
            Span<byte> challengeInput = stackalloc byte[sizeof(uint) + message.Length];
            MemoryMarshal.Write(challengeInput, ref R);
            message.CopyTo(challengeInput.Slice(sizeof(uint)));
            Span<byte> challengeHash = stackalloc byte[32];
            SHA256.HashData(challengeInput, challengeHash);
            ulong c = MemoryMarshal.Read<ulong>(challengeHash);

            // 2. Verify the core Schnorr equation: s*G == R + c*publicKey

            //    Calculate Left Side: s*G
            uint leftSide = StandardCurve.Ambulate(G, s);

            //    Calculate Right Side: R + c*publicKey
            //    First, compute the c*publicKey part.
            uint tempPoint = StandardCurve.Ambulate(publicKey, c);
            //    Then, "add" R to it.
            uint rightSide = StandardCurve.Associate(R, tempPoint);

            // 3. The signature is valid if and only if both sides match.
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
            Console.WriteLine("--- Synthetic Curve Digital Signature Scheme Demo ---");

            // 1. Alice generates her key pair. She keeps the private key secret
            //    and can publish her public key.
            var (alicePrivate, alicePublic) = SignatureScheme.GenerateKeyPair();
            Console.WriteLine($"\nAlice's Public Key (a 'point' on the curve): {alicePublic}");

            // 2. Alice signs a message with her private key.
            var message = "This is a message from Alice."u8.ToArray();
            Console.WriteLine($"\nSigning message: \"{System.Text.Encoding.UTF8.GetString(message)}\"");
            var signature = SignatureScheme.Sign(alicePrivate, message);
            Console.WriteLine($"Signature: (R={signature.R}, s={signature.s})");

            // 3. Bob, a public verifier, receives the message, signature, and Alice's public key.
            Console.WriteLine("\nBob verifies the signature...");
            bool isValid = SignatureScheme.Verify(alicePublic, message, signature);
            Console.WriteLine(isValid ? "SUCCESS: Signature is valid." : "FAILURE: Signature is invalid.");

            // 4. Eve tries to use Alice's signature with a different message.
            var tamperedMessage = "This is a message from Eve!"u8.ToArray();
            Console.WriteLine("\nEve attempts to validate the signature against a tampered message...");
            bool isTamperedValid = SignatureScheme.Verify(alicePublic, tamperedMessage, signature);
            Console.WriteLine(!isTamperedValid ? "SUCCESS: Forgery attempt correctly rejected." : "FAILURE: Forgery attempt was accepted.");

            // 5. Demonstrate that a different key pair fails verification.
            var (bobPrivate, bobPublic) = SignatureScheme.GenerateKeyPair();
            Console.WriteLine("\nBob verifies Alice's signature with his own public key...");
            bool isBobKeyValid = SignatureScheme.Verify(bobPublic, message, signature);
            Console.WriteLine(!isBobKeyValid ? "SUCCESS: Verification with wrong public key correctly failed." : "FAILURE: Verification with wrong key was accepted.");
        }
    }



}
