// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SFStepJump
    //          cd SFStepJump
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// A toy implementation of the Synthetic Field (SF) primitive.
    /// This version uses 'Step' and 'Jump' as its core, content-directed operations.
    /// </summary>
    public sealed class SyntheticField
    {
        internal readonly uint[] _secretDomain;

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
        }

        // --- Core Primitive Operations ---

        /// <summary>
        /// A commutative, fundamental "step" operation.
        /// It combines two domain values to determine a new location in the domain.
        /// </summary>
        /// <param name="valueA">The first value.</param>
        /// <param name="valueB">The second value.</param>
        /// <returns>A new value from the secret domain.</returns>
        public uint Step(uint valueA, uint valueB)
        {
            // To make Step(A, B) == Step(B, A), we sort the inputs.
            if (valueA > valueB) (valueA, valueB) = (valueB, valueA);

            // Find the indices of the input values.
            int indexA = Array.BinarySearch(_secretDomain, valueA);
            int indexB = Array.BinarySearch(_secretDomain, valueB);

            // If either value is not in our domain, the operation is undefined for this toy.
            if (indexA < 0 || indexB < 0)
            {
                // Fallback: A simple hash combination for non-domain values.
                Span<byte> buffer = stackalloc byte[sizeof(uint) * 2];
                MemoryMarshal.Write(buffer, ref valueA);
                MemoryMarshal.Write(buffer.Slice(sizeof(uint)), ref valueB);
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(buffer, hash);
                return MemoryMarshal.Read<uint>(hash); // This value is likely not in the domain.
            }

            // The new index is a simple combination of the input indices, wrapped around the domain size.
            uint newIndex = ((uint)indexA + (uint)indexB) % (uint)_secretDomain.Length;
            return _secretDomain[newIndex];
        }

        /// <summary>
        /// A one-way, "jump" operation, implemented as repeated stepping.
        /// This is analogous to exponentiation (g^a).
        /// </summary>
        /// <param name="startValue">The starting value in the domain (our 'base').</param>
        /// <param name="scalar">A private value determining the number of steps.</param>
        /// <returns>A new value from the secret domain after the jump.</returns>
        public uint Jump(uint startValue, uint scalar)
        {
            // For this toy, we'll make the number of steps small and derived from the scalar.
            // A real system would use a more robust method to prevent timing attacks.
            uint numSteps = (scalar % 8) + 1; // A small number of steps (1 to 8)

            uint currentValue = startValue;
            uint stepValue = scalar; // The scalar itself will be used as the initial "stepper".

            for (int i = 0; i < numSteps; i++)
            {
                // We take a step from our current position using our current 'stepValue'.
                uint nextValue = Step(currentValue, stepValue);

                // To make it more dynamic and less predictable, the result of the step
                // becomes the 'stepper' for the next iteration. This is a form of
                // content-directed navigation.
                currentValue = nextValue;
                stepValue = nextValue;
            }

            return currentValue;
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Synthetic Field Primitive Demo (Step/Jump) ---");

            // --- Setup ---
            byte[] sharedSeed = new byte[32];
            RandomNumberGenerator.Fill(sharedSeed);
            var sf = new SyntheticField(sharedSeed);

            // Reflection is used here just for the demo to peek inside the private field.
            var domain = sf._secretDomain;

            uint valA = domain[10];
            uint valB = domain[20];

            Console.WriteLine($"\nPicked two values from the domain: A={valA}, B={valB}\n");

            // --- Demonstrate Commutative Step ---
            Console.WriteLine("--- Testing Step Operation ---");
            uint step_AB = sf.Step(valA, valB);
            uint step_BA = sf.Step(valB, valA);
            Console.WriteLine($"Step(A, B) => {step_AB}");
            Console.WriteLine($"Step(B, A) => {step_BA}");
            Console.WriteLine(step_AB == step_BA ? "SUCCESS: Step is commutative." : "FAILURE: Step is not commutative.");

            // --- Demonstrate One-Way Jump ---
            Console.WriteLine("\n--- Testing Jump Operation ---");
            uint privateScalar = 123456789;
            uint generatorG = domain[0]; // The public generator is the first element.

            Console.WriteLine($"Generator G = {generatorG}");
            Console.WriteLine($"Private Scalar = {privateScalar}");

            uint jump_result = sf.Jump(generatorG, privateScalar);
            Console.WriteLine($"Jump(G, Scalar) => {jump_result}");
            Console.WriteLine("This result is a public token (like g^a).");
            Console.WriteLine("It should be computationally difficult to find 'Private Scalar' given G and the result.");
        }
    }


}
