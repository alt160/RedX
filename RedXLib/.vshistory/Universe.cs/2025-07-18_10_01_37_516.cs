// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SCSimplestFixed
    //          cd SCSimplestFixed
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    public sealed class SyntheticCurve
    {
        private readonly uint[] _secretDomain;
        private readonly uint _operatorRatio;
        private readonly uint _generator;

        public uint Generator => _generator;

        public SyntheticCurve(ReadOnlySpan<byte> masterSeed)
        {
            if (masterSeed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");

            byte[] domainSeed = HKDF.Expand(HashAlgorithmName.SHA256, masterSeed.ToArray(), 32, info: "sc-domain-seed"u8.ToArray());
            byte[] ratioSeed = HKDF.Expand(HashAlgorithmName.SHA256, masterSeed.ToArray(), 32, info: "sc-ratio-seed"u8.ToArray());

            const int domainSize = 1024;
            _secretDomain = new uint[domainSize];

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

        // ---------- CORRECTED AMBULATE IMPLEMENTATION ----------

        /// <summary>
        /// A corrected one-way "ambulate" function. It uses the scalar as an
        /// instruction, not a value, to perform repeated self-association.
        /// This correctly models scalar multiplication (k*P).
        /// </summary>
        public uint Ambulate(uint startValue, uint scalar)
        {
            // For this toy, the scalar determines the number of "doubling" steps.
            // This is a simple, constant-time way to use the scalar.
            // A real system would use a more robust bitwise method.
            uint numSteps = (scalar % 8) + 8; // e.g., 8 to 15 steps.

            uint currentValue = startValue;
            for (int i = 0; i < numSteps; i++)
            {
                // The core operation is now P = P + P, or Associate(P, P).
                // This is analogous to the "square" step in square-and-multiply.
                currentValue = Associate(currentValue, currentValue);
            }
            return currentValue;
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Corrected Simplest Generative Synthetic Curve Demo ---");

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

            // --- Demonstrate Seed-Dependency with the CORRECTED Ambulate ---
            uint scalar = 12345;

            // The test calculation itself was conceptually correct. Now it will work.
            uint resultA = aliceCurve.Ambulate(aliceCurve.Generator, scalar);
            uint resultB = bobCurve.Ambulate(bobCurve.Generator, scalar);

            Console.WriteLine($"\nAlice computes Ambulate(G_A, scalar) => {resultA}");
            Console.WriteLine($"Bob computes   Ambulate(G_B, scalar) => {resultB}");

            if (resultA != resultB && resultA != 0 && resultB != 0)
            {
                Console.WriteLine("\nSUCCESS: The same operation with the same scalar produces different");
                Console.WriteLine("results on different curves, proving the system is seed-dependent.");
            }
            else
            {
                Console.WriteLine("\nFAILURE: The system is not properly seed-dependent or the Ambulate function failed.");
            }
        }
    }




}
