// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SFToy
    //          cd SFToy
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Buffers.Binary;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// A toy implementation of the Synthetic Field (SF) primitive.
    /// This class demonstrates the core concepts of a preshared secret domain
    /// and the operations needed for a rendezvous.
    /// </summary>
    public sealed class SyntheticField
    {
        // The preshared secret domain, generated from a seed.
        // In a real system, this would be much larger. For this toy, it's unused
        // but shown to represent the full architectural concept.
        private readonly uint[] _secretDomain;

        /// <summary>
        /// Creates a Synthetic Field from a secret seed.
        /// Both parties must use the same seed to generate the same domain.
        /// </summary>
        /// <param name="seed">A 32-byte (256-bit) secret seed.</param>
        /// <param name="domainSize">The number of elements in the field.</param>
        public SyntheticField(ReadOnlySpan<byte> seed, int domainSize = 1024)
        {
            if (seed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");

            // ---------- MODIFIED SECTION START ----------

            _secretDomain = new uint[domainSize];

            // We deterministically expand the seed into the full secret domain.
            // This KDF-like process uses the seed and a counter to generate each value.
            Span<byte> hashOutput = stackalloc byte[32];
            Span<byte> inputBuffer = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(inputBuffer);

            for (int i = 0; i < domainSize; i++)
            {
                // Write the current index to the buffer to ensure each hash input is unique.
                MemoryMarshal.Write(inputBuffer.Slice(seed.Length), ref i);

                // Generate a hash based on the seed and counter.
                SHA256.HashData(inputBuffer, hashOutput);

                // The value is a "random" 32-bit uint derived from the hash.
                // This decouples the value from its index position.
                _secretDomain[i] = MemoryMarshal.Read<uint>(hashOutput);
            }

            // As requested, sort the list of random integers.
            // This gives the domain a specific, deterministic structure derived from the seed.
            // A sorted domain allows for very fast lookups (binary search) if needed later.
            Array.Sort(_secretDomain);

            // Note: A production system might want to handle the astronomically rare case of
            // duplicate values after generation, for instance by re-rolling them.
            // For this toy, we assume all generated values are unique.

            Console.WriteLine($"Toy SF initialized. Domain populated with {domainSize} sorted values.");

            // ---------- MODIFIED SECTION END ----------
        }



        /// <summary>
        /// The 'Transform' operation.
        /// NOTE: This simple version still does NOT use the secret domain. That's our next step.
        /// </summary>
        public uint Transform(uint secret)
        {
            Span<byte> inputBuffer = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32LittleEndian(inputBuffer, secret);

            Span<byte> hashOutput = stackalloc byte[32];
            SHA256.HashData(inputBuffer, hashOutput);

            return MemoryMarshal.Read<uint>(hashOutput);
        }



        /// <summary>
        /// The 'Combine' operation.
        /// NOTE: This simple version still does NOT use the secret domain.
        /// </summary>
        public uint Combine(uint myTransformedValue, uint theirTransformedValue)
        {
            uint val1 = myTransformedValue;
            uint val2 = theirTransformedValue;

            if (val1 > val2) (val1, val2) = (val2, val1);

            Span<byte> inputBuffer = stackalloc byte[sizeof(uint) * 2];
            BinaryPrimitives.WriteUInt32LittleEndian(inputBuffer, val1);
            BinaryPrimitives.WriteUInt32LittleEndian(inputBuffer.Slice(sizeof(uint)), val2);

            Span<byte> hashOutput = stackalloc byte[32];
            SHA256.HashData(inputBuffer, hashOutput);

            return MemoryMarshal.Read<uint>(hashOutput);
        }

    }

        public static class Program
        {
            public static void Main()
            {
                Console.WriteLine("--- Toy Synthetic Field Rendezvous Demo ---");
                Console.WriteLine("Goal: Alice and Bob arrive at the same secret value without sharing their secrets.\n");

                // --- Setup ---
                // 1. Alice and Bob must securely agree on a seed beforehand.
                byte[] sharedSeed = new byte[32];
                RandomNumberGenerator.Fill(sharedSeed);

                // 2. Both create an identical instance of the Synthetic Field using the shared seed.
                //    We only need one instance here to represent this shared state.
                var sharedField = new SyntheticField(sharedSeed);

                // 3. Alice and Bob choose their ephemeral private secrets for this session.
                uint secret_A = 12345; // Alice's secret
                uint secret_B = 67890; // Bob's secret
                Console.WriteLine($"Alice's private secret (a): {secret_A}");
                Console.WriteLine($"Bob's private secret (b):   {secret_B}\n");

                // --- The Protocol Exchange ---
                // 1. Alice transforms her secret into a public value.
                uint transformed_A = sharedField.Transform(secret_A);
                Console.WriteLine($"Alice computes Transformed(a) -> {transformed_A} (sends to Bob)");

                // 2. Bob transforms his secret into a public value.
                uint transformed_B = sharedField.Transform(secret_B);
                Console.WriteLine($"Bob computes Transformed(b)   -> {transformed_B} (sends to Alice)\n");

                // --- The Rendezvous ---
                // 3. Alice receives Bob's value and combines it with her own transformed value.
                uint sharedValue_A = sharedField.Combine(transformed_A, transformed_B);
                Console.WriteLine($"Alice computes Combine({transformed_A}, {transformed_B}) -> {sharedValue_A}");

                // 4. Bob receives Alice's value and combines it with his own transformed value.
                uint sharedValue_B = sharedField.Combine(transformed_B, transformed_A);
                Console.WriteLine($"Bob computes   Combine({transformed_B}, {transformed_A}) -> {sharedValue_B}\n");

                // --- Verification of the Rendezvous ---
                if (sharedValue_A == sharedValue_B)
                {
                    Console.WriteLine("SUCCESS: Alice and Bob arrived at the same secret value.");
                }
                else
                {
                    Console.WriteLine("FAILURE: The values do not match.");
                }

                // --- The Security Context (The Catch) ---
                Console.WriteLine("\n--- Security Analysis ---");
                Console.WriteLine("An eavesdropper, Eve, sees the public exchange.");
                Console.WriteLine($"Eve intercepts Transformed(a) = {transformed_A}");
                Console.WriteLine($"Eve intercepts Transformed(b) = {transformed_B}");

                // Eve can perform the exact same public 'Combine' operation.
                uint eveSharedValue = sharedField.Combine(transformed_A, transformed_B);
                Console.WriteLine($"Eve computes Combine({transformed_A}, {transformed_B}) -> {eveSharedValue}");

                if (eveSharedValue == sharedValue_A)
                {
                    Console.WriteLine("CONCLUSION: The Rendezvous works, but this simple toy primitive is NOT secure.");
                    Console.WriteLine("The next step in the design is to create 'Transform' and 'Combine' functions");
                    Console.WriteLine("that prevent this eavesdropping, likely using Content-Directed Navigation.");
                }
            }
        }
    }
