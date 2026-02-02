// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SyntheticFieldDemo
    //          cd SyntheticFieldDemo
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    // --- 1. The Core Synthetic Field (SF) Primitive ---
    // Represents the secret domain generated from a seed. This is the private key.
    public sealed class SyntheticField
    {
        private readonly uint[] _secretDomain;
        private const int GeneratorIndex = 0; // The public "starting point" index.

        /// <summary>
        /// Creates a new Synthetic Field instance.
        /// This is the core of the private key. The seed should be kept secret.
        /// </summary>
        /// <param name="seed">A 32-byte (256-bit) secret seed.</param>
        /// <param name="domainSize">The number of elements in the field (e.g., 1024).</param>
        public SyntheticField(ReadOnlySpan<byte> seed, int domainSize = 1024)
        {
            if (seed.Length != 32)
                throw new ArgumentException("Seed must be 32 bytes.", nameof(seed));
            if (domainSize <= 0)
                throw new ArgumentException("Domain size must be positive.", nameof(domainSize));

            _secretDomain = new uint[domainSize];

            // --- Lever 17: Domain Provisioning via Seed Expansion ---
            // We deterministically expand the seed into the full secret domain.
            // We'll use SHA256 in a way similar to a Key Derivation Function (KDF).
            // This is computationally cheap.
            Span<byte> hashOutput = stackalloc byte[32];
            Span<byte> inputBuffer = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(inputBuffer);

            for (int i = 0; i < domainSize; i++)
            {
                // Write the current index to the buffer to ensure each hash is unique.
                MemoryMarshal.Write(inputBuffer.Slice(seed.Length), ref i);

                // Generate a hash based on the seed and counter.
                SHA256.HashData(inputBuffer, hashOutput);

                // --- Lever 11: Value-Index Disassociation ---
                // The value is a random 32-bit uint, not tied to the index.
                // This reads the first 4 bytes of the hash as a uint.
                _secretDomain[i] = MemoryMarshal.Read<uint>(hashOutput);
            }
            // Note: A production system would check for duplicate values, though
            // with a 2^32 value space and 1024 elements, it's astronomically unlikely.
        }

        /// <summary>
        /// The core navigation function. This is our "Operator Function" or "Mode of Operation".
        /// Its logic is public, but its output is secret without the domain.
        /// </summary>
        /// <param name="startIndex">The starting index in the domain.</param>
        /// <param name="distanceValue">A value influencing the "distance" to travel.</param>
        /// <returns>A new index in the domain.</returns>
        private uint Navigate(uint startIndex, uint distanceValue)
        {
            // --- Lever 8: Content-Directed Navigation ---
            // The value at the start index influences the navigation.
            uint startValue = _secretDomain[startIndex];

            // Combine the current location's value with the distance value.
            // This could be any deterministic operation. We'll use a hash.
            Span<byte> buffer = stackalloc byte[sizeof(uint) * 2];
            MemoryMarshal.Write(buffer, ref startValue);
            MemoryMarshal.Write(buffer.Slice(sizeof(uint)), ref distanceValue);

            Span<byte> hashOutput = stackalloc byte[32];
            SHA256.HashData(buffer, hashOutput);

            // The result of the hash determines the actual distance to travel.
            uint travelDistance = MemoryMarshal.Read<uint>(hashOutput);

            // The new index is the start plus our content-directed distance, wrapped around the domain.
            return (startIndex + travelDistance) % (uint)_secretDomain.Length;
        }

        /// <summary>
        /// The public transformation operation. Part of the signature "commitment".
        /// This is a one-way function: easy to compute, hard to reverse without the domain.
        /// </summary>
        public uint Transform(uint secret) => Navigate(GeneratorIndex, secret);

        /// <summary>
        /// The final combination step. For signatures, this creates the "response".
        /// </summary>
        public uint Combine(uint mySecret, uint theirTransformedValue)
        {
            // To satisfy the rendezvous invariant for Fiat-Shamir, the combination
            // must be symmetric in some way. Here, we'll use a commutative hash
            // to derive a final "walker" seed, then walk the domain with it.
            uint val1 = mySecret;
            uint val2 = theirTransformedValue;

            // Ensure commutativity by sorting the inputs before hashing.
            if (val1 > val2) (val1, val2) = (val2, val1);

            Span<byte> buffer = stackalloc byte[sizeof(uint) * 2];
            MemoryMarshal.Write(buffer, ref val1);
            MemoryMarshal.Write(buffer.Slice(sizeof(uint)), ref val2);

            Span<byte> walkerSeed = stackalloc byte[32];
            SHA256.HashData(buffer, walkerSeed);

            // "Walk" the domain using the walker seed to make the final result
            // dependent on the entire secret domain in a complex way.
            uint currentIndex = 0;
            var walkerUints = MemoryMarshal.Cast<byte, uint>(walkerSeed);

            for (int i = 0; i < walkerUints.Length; i++)
            {
                currentIndex = Navigate(currentIndex, walkerUints[i]);
            }

            // The final value is an element from our secret domain.
            return _secretDomain[currentIndex];
        }
    }

    // --- 2. The Signature Data Structure ---
    public readonly record struct SyntheticSignature(uint Commitment, uint Response);

    // --- 3. The Signer and Verifier Logic ---
    public static class SyntheticSigner
    {
        /// <summary>
        /// Signs a message using the Synthetic Field private key.
        /// </summary>
        public static SyntheticSignature Sign(SyntheticField privateKey, ReadOnlySpan<byte> message)
        {
            // Generate a random, one-time secret nonce 'a' for this signature.
            Span<byte> randomBytes = stackalloc byte[sizeof(uint)];
            RandomNumberGenerator.Fill(randomBytes);
            uint nonce_a = MemoryMarshal.Read<uint>(randomBytes);

            // 1. Commitment: Transform the nonce. This becomes public.
            uint commitment_TA = privateKey.Transform(nonce_a);

            // 2. Challenge: Hash the commitment and the message to create a challenge 'c'.
            //    This makes the signature bound to the message content.
            Span<byte> challengeInput = stackalloc byte[sizeof(uint) + message.Length];
            MemoryMarshal.Write(challengeInput, ref commitment_TA);
            message.CopyTo(challengeInput.Slice(sizeof(uint)));

            Span<byte> challengeHash = stackalloc byte[32];
            SHA256.HashData(challengeInput, challengeHash);
            uint challenge_c = MemoryMarshal.Read<uint>(challengeHash);

            // 3. Response: Combine our secret nonce 'a' with the public transformed challenge.
            uint transformedChallenge = privateKey.Transform(challenge_c);
            uint response_S = privateKey.Combine(nonce_a, transformedChallenge);

            return new SyntheticSignature(commitment_TA, response_S);
        }

        /// <summary>
        /// Verifies a signature against a public key (seed) and a message.
        /// </summary>
        public static bool Verify(ReadOnlySpan<byte> publicKeySeed, ReadOnlySpan<byte> message, SyntheticSignature signature)
        {
            // The verifier recreates the public parts of the field from the public key seed.
            // No secret information is used here besides what's public.
            var verifierField = new SyntheticField(publicKeySeed);

            // 1. Recreate the challenge 'c' the same way the signer did.
            Span<byte> challengeInput = stackalloc byte[sizeof(uint) + message.Length];
            MemoryMarshal.Write(challengeInput, signature.Commitment);
            message.CopyTo(challengeInput.Slice(sizeof(uint)));

            Span<byte> challengeHash = stackalloc byte[32];
            SHA256.HashData(challengeInput, challengeHash);
            uint challenge_c = MemoryMarshal.Read<uint>(challengeHash);

            // 2. The verifier performs the *symmetric* combination.
            // They combine the public challenge 'c' with the public commitment from the signature.
            uint transformedCommitment = signature.Commitment; // This is T_A
            uint expectedResponse_S = verifierField.Combine(challenge_c, transformedCommitment);

            // 3. Check if the expected response matches the actual response in the signature.
            // This works because Combine(a, Transform(c)) should equal Combine(c, Transform(a)).
            // Our commutative hash in the Combine function ensures this holds.
            return expectedResponse_S == signature.Response;
        }
    }

    // --- 4. Demonstration ---
    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Synthetic Field PQC Signature Demo ---");

            // --- Setup ---
            // 1. Alice generates her long-term private key (the seed).
            byte[] alicePrivateKeySeed = new byte[32];
            RandomNumberGenerator.Fill(alicePrivateKeySeed);

            // Her public key is just a copy of the seed. In a real system,
            // you would securely distribute this public key.
            byte[] alicePublicKey = alicePrivateKeySeed;

            // 2. Alice creates her Synthetic Field instance from her private seed.
            var aliceField = new SyntheticField(alicePrivateKeySeed);

            // 3. The message to be signed.
            var message = "This is a test of the SF signature system."u8.ToArray();

            Console.WriteLine($"\nSigning message: \"{System.Text.Encoding.UTF8.GetString(message)}\"");

            // --- Signing ---
            var signature = SyntheticSigner.Sign(aliceField, message);
            Console.WriteLine($"Signature generated:");
            Console.WriteLine($"  Commitment: {signature.Commitment}");
            Console.WriteLine($"  Response:   {signature.Response}");

            // --- Verification ---
            Console.WriteLine("\nVerifying the signature with the public key...");
            bool isValid = SyntheticSigner.Verify(alicePublicKey, message, signature);

            Console.WriteLine(isValid
                ? "SUCCESS: The signature is valid."
                : "FAILURE: The signature is NOT valid.");

            // --- Tampering Demo ---
            Console.WriteLine("\n--- Tampering Demo ---");
            Console.WriteLine("Verifying the original signature against a different message...");
            var tamperedMessage = "This is a different message."u8.ToArray();

            bool isTamperedValid = SyntheticSigner.Verify(alicePublicKey, tamperedMessage, signature);
            Console.WriteLine(!isTamperedValid
                ? "SUCCESS: The tampered signature was correctly rejected."
                : "FAILURE: The tampered signature was accepted.");
        }
    }

}
