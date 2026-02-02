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
            // --- Lever 17: Domain Provisioning via Seed Expansion ---
            // This demonstrates generating the large secret domain from a small, shared seed.
            // The computational cost is very low.
            if (seed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");

            _secretDomain = new uint[domainSize];
            // For this toy, we won't populate it yet to keep the focus on the rendezvous logic.
            // In a real implementation, you would use a method like in our previous example
            // (e.g., hashing the seed + a counter) to fill this array.
            Console.WriteLine($"Toy SF initialized. (Domain size: {_secretDomain.Length} elements).");
        }

        /// <summary>
        /// The 'Transform' operation.
        /// A party uses this to transform their private secret into a public token.
        /// NOTE: For this simple toy, we are not using the secret domain in this step,
        /// focusing only on the protocol flow.
        /// </summary>
        /// <param name="secret">A private value chosen by a party.</param>
        /// <returns>A public value to be exchanged.</returns>
        public uint Transform(uint secret)
        {
            Span<byte> inputBuffer = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32LittleEndian(inputBuffer, secret);

            Span<byte> hashOutput = stackalloc byte[32];
            SHA256.HashData(inputBuffer, hashOutput);

            // We'll use the first 4 bytes of the hash as our transformed value.
            // This is a one-way operation: given the output, it's hard to find the input 'secret'.
            return MemoryMarshal.Read<uint>(hashOutput);
        }

        /// <summary>
        /// The 'Combine' operation.
        /// Both parties use this to arrive at the final shared value.
        /// </summary>
        /// <param name="myTransformedValue">The value *I* created with Transform().</param>
        /// <param name="theirTransformedValue">The value *they* sent me.</param>
        /// <returns>The final, shared rendezvous value.</returns>
        public uint Combine(uint myTransformedValue, uint theirTransformedValue)
        {
            // To ensure both parties arrive at the same result regardless of order,
            // we must make this operation commutative. Sorting the inputs before
            // processing them is the simplest way to achieve this in code.
            uint val1 = myTransformedValue;
            uint val2 = theirTransformedValue;

            if (val1 > val2) (val1, val2) = (val2, val1); // Swap if needed

            // Now we combine the canonicalized (sorted) inputs.
            Span<byte> inputBuffer = stackalloc byte[sizeof(uint) * 2];
            BinaryPrimitives.WriteUInt32LittleEndian(inputBuffer, val1);
            BinaryPrimitives.WriteUInt32LittleEndian(inputBuffer.Slice(sizeof(uint)), val2);

            Span<byte> hashOutput = stackalloc byte[32];
            SHA256.HashData(inputBuffer, hashOutput);

            // The final shared value is derived from this combined hash.
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
