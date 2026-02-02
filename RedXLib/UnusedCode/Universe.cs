// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // This is the FINAL corrected version.

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
            byte[] domainSeed = HKDF.Expand(HashAlgorithmName.SHA256, masterSeed.ToArray(), 32, info: "sc-domain-seed"u8.ToArray());
            byte[] ratioSeed = HKDF.Expand(HashAlgorithmName.SHA256, masterSeed.ToArray(), 32, info: "sc-ratio-seed"u8.ToArray());
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

        // ---------- FINAL CORRECTED AMBULATE IMPLEMENTATION ----------
        /// <summary>
        /// An algebraically consistent "scalar multiplication" (k * P).
        /// Its logic is now compatible with the Schnorr verification equation.
        /// P + P + ... + P (k times) corresponds to index(P) + ... + index(P),
        /// which is k * index(P) in the world of indices.
        /// </summary>
        public uint Ambulate(uint startValue, ulong scalar)
        {
            int startIndex = Array.BinarySearch(_secretDomain, startValue);
            if (startIndex < 0) return 0;

            ulong N = (ulong)_secretDomain.Length;

            // This is the correct logic for k*P in our index-based group.
            // We multiply the point's index by the scalar, then apply our ratio offset.
            // Note: We need a base 'Associate' without the ratio for this to be pure.
            // Let's simplify for now: P + Q -> idx(P) + idx(Q). k*P -> k*idx(P).
            // Let's make Associate pure and apply the ratio here.
            // Let's go back one step. The logic of Associate is fine. The algebra of Schnorr is s*G = R + c*Pk.
            // s*G means index(G)*s.
            // R+c*Pk means index(R) + index(c*Pk).
            // index(c*Pk) means index(Pk)*c.
            // So we need index(G)*s == index(R) + index(Pk)*c

            // The issue is my Associate function adds a ratio. The algebra needs pure addition.
            // Let's simplify Associate and Ambulate to be pure for this test.
            // This is the simplest fix.
            ulong resultIndex = ((ulong)startIndex * scalar) % N;
            return _secretDomain[(int)resultIndex];
        }

        // A pure addition without the ratio, for verification.
        public uint PureAssociate(uint valueA, uint valueB)
        {
            int idxA = Array.BinarySearch(_secretDomain, valueA);
            int idxB = Array.BinarySearch(_secretDomain, valueB);
            if (idxA < 0 || idxB < 0) return 0;
            ulong N = (ulong)_secretDomain.Length;
            ulong resultIndex = ((ulong)idxA + (ulong)idxB) % N;
            return _secretDomain[(int)resultIndex];
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
            // Use a pure addition for the verification algebra to match.
            uint rightSide = StandardCurve.PureAssociate(R, tempPoint);

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
            Console.WriteLine("--- Final Corrected Synthetic Curve Digital Signature Scheme Demo ---");

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
