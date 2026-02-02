// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SCSimplest
    //          cd SCSimplest
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// The simplest possible implementation of a "Generative" Synthetic Curve.
    /// It demonstrates how a single seed can define the domain, the operator,
    /// and the generator.
    /// </summary>
    public sealed class SyntheticCurve
    {
        // The "Gears" of our Spirograph, all derived from the master seed.
        private readonly uint[] _secretDomain;    // The Outer Ring
        private readonly uint _operatorRatio;     // The Inner Shape's "Ratio"
        private readonly uint _generator;         // The Pen Placement

        public uint Generator => _generator;

        public SyntheticCurve(ReadOnlySpan<byte> masterSeed)
        {
            if (masterSeed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");

            // --- Use a KDF to derive separate seeds for each component ---
            // This is a crucial step for security, even in a simple model.
            byte[] domainSeed = HKDF.Expand(HashAlgorithmName.SHA256, masterSeed.ToArray(), 32, info: "sc-domain-seed"u8.ToArray());
            byte[] ratioSeed = HKDF.Expand(HashAlgorithmName.SHA256, masterSeed.ToArray(), 32, info: "sc-ratio-seed"u8.ToArray());

            // --- 1. Generate the "Outer Ring" (The Domain) ---
            // For our simplest model, the size is fixed.
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

            // --- 2. Generate the "Inner Shape" (The Operator Ratio) ---
            // For our simplest model, the "ratio" is just a single uint derived from the ratioSeed.
            _operatorRatio = MemoryMarshal.Read<uint>(ratioSeed);

            // --- 3. Generate the "Pen Placement" (The Generator) ---
            // Holistically derive the generator from the final domain content.
            ReadOnlySpan<byte> domainAsBytes = MemoryMarshal.AsBytes<uint>(_secretDomain);
            SHA256.HashData(domainAsBytes, hashOutput);
            uint generatorIndexSeed = MemoryMarshal.Read<uint>(hashOutput);
            int generatorIndex = (int)(generatorIndexSeed % (uint)domainSize);
            _generator = _secretDomain[generatorIndex];
        }

        /// <summary>
        /// The simplest possible associative operation, now parameterized by our secret ratio.
        /// Its behavior is different for every seed.
        /// </summary>
        public uint Associate(uint valueA, uint valueB)
        {
            int idxA = Array.BinarySearch(_secretDomain, valueA);
            int idxB = Array.BinarySearch(_secretDomain, valueB);
            if (idxA < 0 || idxB < 0) return 0; // Error case

            // The operation's result is now influenced by the secret _operatorRatio.
            ulong N = (ulong)_secretDomain.Length;
            ulong resultIndex = ((ulong)idxA + (ulong)idxB + _operatorRatio) % N;

            return _secretDomain[(int)resultIndex];
        }

        // A simple Ambulate (Jump) function for demonstration.
        // It uses the parameterized Associate function.
        public uint Ambulate(uint startValue, uint scalar)
        {
            const int numRounds = 16;
            uint currentValue = startValue;
            for (int i = 0; i < numRounds; i++)
            {
                // The scalar itself can be the "other" value in the association.
                // Each step is now influenced by the secret ratio.
                currentValue = Associate(currentValue, scalar);
            }
            return currentValue;
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Simplest Generative Synthetic Curve Demo ---");

            // --- Alice's Setup ---
            byte[] aliceSeed = new byte[32];
            RandomNumberGenerator.Fill(aliceSeed);
            var aliceCurve = new SyntheticCurve(aliceSeed);
            Console.WriteLine($"\nAlice's curve generated. Generator G_A = {aliceCurve.Generator}");

            // --- Bob's Setup ---
            byte[] bobSeed = new byte[32];
            RandomNumberGenerator.Fill(bobSeed);
            var bobCurve = new SyntheticCurve(bobSeed);
            Console.WriteLine($"Bob's curve generated.   Generator G_B = {bobCurve.Generator}");

            Console.WriteLine("\nNotice that Alice and Bob have different generators because their");
            Console.WriteLine("secret seeds are different, which created different secret domains.");

            // --- Demonstrate Seed-Dependency ---
            uint scalar = 12345;

            uint resultA = aliceCurve.Ambulate(aliceCurve.Generator, scalar);
            uint resultB = bobCurve.Ambulate(bobCurve.Generator, scalar);

            Console.WriteLine($"\nAlice computes Ambulate(G_A, scalar) => {resultA}");
            Console.WriteLine($"Bob computes   Ambulate(G_B, scalar) => {resultB}");

            if (resultA != resultB)
            {
                Console.WriteLine("\nSUCCESS: The same operation with the same scalar produces different");
                Console.WriteLine("results on different curves, proving the system is seed-dependent.");
            }
            else
            {
                Console.WriteLine("\nFAILURE: The system is not properly seed-dependent.");
            }
        }
    }





}
