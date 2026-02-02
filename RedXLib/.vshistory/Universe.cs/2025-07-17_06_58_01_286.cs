// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SFPrimitive
    //          cd SFPrimitive
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Buffers.Binary;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// A toy implementation of the Synthetic Field (SF) primitive.
    /// This class encapsulates a secret domain and provides two core,
    /// content-directed operations: a commutative 'Add' and a one-way 'Multiply'.
    /// </summary>
    public sealed class SyntheticField
    {
        internal readonly uint[] _secretDomain;

        /// <summary>
        /// Creates a Synthetic Field from a secret seed.
        /// This object represents a shared secret context.
        /// </summary>
        public SyntheticField(ReadOnlySpan<byte> seed, int domainSize = 1024)
        {
            if (seed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");

            _secretDomain = new uint[domainSize];

            Span<byte> hashOutput = stackalloc byte[32];
            Span<byte> inputBuffer = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(inputBuffer);

            for (int i = 0; i < domainSize; i++)
            {
                MemoryMarshal.Write(inputBuffer.Slice(seed.Length), ref i);
                SHA256.HashData(inputBuffer, hashOutput);
                _secretDomain[i] = MemoryMarshal.Read<uint>(hashOutput);
            }

            Array.Sort(_secretDomain);
            Console.WriteLine($"SF Primitive initialized. Domain populated with {domainSize} sorted values.");
        }

        // --- Core Primitive Operations ---

        /// <summary>
        /// A commutative, "add-like" operation.
        /// It combines two values from within the secret domain to produce a third.
        /// The operation is deterministic but unpredictable without the domain.
        /// </summary>
        /// <param name="a">The first value.</param>
        /// <param name="b">The second value.</param>
        /// <returns>A new value from the secret domain.</returns>
        public uint Add(uint a, uint b)
        {
            // To achieve commutativity (a + b == b + a), we sort the inputs.
            if (a > b) (a, b) = (b, a);

            // This operation's logic is public, but its result depends on the secret domain.
            // We find the indices of the input values. This is only possible because we
            // have the _secretDomain. Since the domain is sorted, we can use a fast binary search.
            int indexA = Array.BinarySearch(_secretDomain, a);
            int indexB = Array.BinarySearch(_secretDomain, b);

            // If a value is not in our domain, the operation is undefined for this toy.
            // A real system would define specific error handling.
            if (indexA < 0 || indexB < 0)
            {
                // For this toy, we'll just return a deterministic hash of the inputs.
                // This is a "fallback" path.
                Span<byte> fallbackBuffer = stackalloc byte[sizeof(uint) * 2];
                MemoryMarshal.Write(fallbackBuffer, ref a);
                MemoryMarshal.Write(fallbackBuffer.Slice(sizeof(uint)), ref b);
                Span<byte> fallbackHash = stackalloc byte[32];
                SHA256.HashData(fallbackBuffer, fallbackHash);
                return MemoryMarshal.Read<uint>(fallbackHash);
            }

            // The new index is a simple combination of the input indices.
            uint newIndex = ((uint)indexA + (uint)indexB) % (uint)_secretDomain.Length;

            // The result is the value at the new index.
            return _secretDomain[newIndex];
        }

        /// <summary>
        /// A one-way, "multiply-like" operation.
        /// This is designed to be our core one-way function, analogous to g^a.
        /// It "multiplies" a domain value (the base) by a scalar (the exponent).
        /// </summary>
        /// <param name="baseValue">A value from within the domain.</param>
        /// <param name="scalar">The private "exponent" or multiplier.</param>
        /// <returns>A new value from the secret domain.</returns>
        public uint Multiply(uint baseValue, uint scalar)
        {
            // Find the starting index for our base value.
            int currentIndex = Array.BinarySearch(_secretDomain, baseValue);
            if (currentIndex < 0)
            {
                // Handle the case where the base is not in the domain.
                // Again, a simple fallback for this toy.
                return MemoryMarshal.Read<uint>(SHA256.HashData(
                    MemoryMarshal.AsBytes(new ReadOnlySpan<uint>(ref baseValue))));
            }

            // --- Content-Directed Navigation ---
            // We will "walk" through the domain in a way that depends on the scalar.
            // This simulates exponentiation by repeated multiplication, but with our 'Add' operation.
            // To make it content-directed, the "scalar" itself doesn't directly define the
            // number of steps. It seeds a pseudo-random walk.
            uint walker = scalar;
            for (int i = 0; i < 4; i++) // A fixed number of "mixing" steps for this toy.
            {
                // The value at the current location directs the next step.
                uint currentValue = _secretDomain[currentIndex];

                // Combine the walker with the current value.
                uint combined = this.Add(walker, currentValue);

                // The result of the Add operation gives us a new index.
                // We find the index of this new combined value to continue our walk.
                currentIndex = Array.BinarySearch(_secretDomain, combined);
                if (currentIndex < 0)
                {
                    // This indicates a hash fallback was used in Add. We'll just use the
                    // hash result as the new walker and continue.
                    walker = combined;
                    currentIndex = (int)(walker % _secretDomain.Length); // Reset index
                }
                else
                {
                    // Update the walker for the next iteration.
                    walker = combined;
                }
            }

            return _secretDomain[currentIndex];
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Synthetic Field Primitive Demo ---");

            // --- Setup ---
            byte[] sharedSeed = new byte[32];
            RandomNumberGenerator.Fill(sharedSeed);
            var sf = new SyntheticField(sharedSeed);
            Console.WriteLine();

            // Let's pick two values that we know are in the domain for our demo.
            // We'll just grab them from the internal array for convenience.
            // To do this properly without exposing the private field, we would
            // need a public method to get values, e.g., `sf.GetValue(index)`.
            uint valA = sf._secretDomain[10];

            uint valB = sf._secretDomain[20];

            Console.WriteLine($"Picked two values from the domain: A={valA}, B={valB}\n");

            // --- Demonstrate Commutative Add ---
            Console.WriteLine("--- Testing Add-like Operation ---");
            uint add_AB = sf.Add(valA, valB);
            uint add_BA = sf.Add(valB, valA);
            Console.WriteLine($"Add(A, B) => {add_AB}");
            Console.WriteLine($"Add(B, A) => {add_BA}");
            Console.WriteLine(add_AB == add_BA ? "SUCCESS: Add is commutative." : "FAILURE: Add is not commutative.");

            // --- Demonstrate One-Way Multiply ---
            Console.WriteLine("\n--- Testing Multiply-like Operation ---");
            uint privateScalar = 123456789;
            // Let's use the first value in the domain as our public generator 'g'.
            uint generatorG = sf._secretDomain[0];

            Console.WriteLine($"Generator G = {generatorG}");
            Console.WriteLine($"Private Scalar = {privateScalar}");

            uint mult_result = sf.Multiply(generatorG, privateScalar);
            Console.WriteLine($"Multiply(G, Scalar) => {mult_result}");
            Console.WriteLine("This result is a public token (like g^a).");
            Console.WriteLine("It should be computationally difficult to find 'Private Scalar' from 'G' and the result.");
        }
    }

}
