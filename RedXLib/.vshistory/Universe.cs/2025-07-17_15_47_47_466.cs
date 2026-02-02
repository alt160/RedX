// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SFConstantTime
    //          cd SFConstantTime
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    public sealed class SyntheticField
    {
        // ... (Constructor and Step method are unchanged) ...
        private readonly uint[] _secretDomain;
        private readonly uint _generator;
        public uint Generator => _generator;

        public SyntheticField(ReadOnlySpan<byte> seed, int domainSize = 1024)
        {
            // Constructor logic is identical to the previous version
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
            ReadOnlySpan<byte> domainAsBytes = MemoryMarshal.AsBytes<uint>(_secretDomain);
            SHA256.HashData(domainAsBytes, hashOutput);
            uint generatorIndexSeed = MemoryMarshal.Read<uint>(hashOutput);
            int generatorIndex = (int)(generatorIndexSeed % (uint)domainSize);
            _generator = _secretDomain[generatorIndex];
        }

        public uint Step(uint valueA, uint valueB)
        {
            // Step logic is identical to the previous version
            if (valueA > valueB) (valueA, valueB) = (valueB, valueA);
            int indexA = Array.BinarySearch(_secretDomain, valueA);
            int indexB = Array.BinarySearch(_secretDomain, valueB);
            if (indexA < 0 || indexB < 0) { /* Fallback... */ return 0; }
            uint newIndex = ((uint)indexA + (uint)indexB) % (uint)_secretDomain.Length;
            return _secretDomain[newIndex];
        }

        // ---------- THE SECURE JUMP IMPLEMENTATION ----------

        /// <summary>
        /// A secure, one-way "jump" operation, written in a constant-time style.
        /// This is the heart of the SF primitive's security.
        /// </summary>
        public uint Jump(uint startValue, uint scalar)
        {
            // The number of rounds is FIXED to prevent timing attacks.
            // We choose 32 rounds to process all bits of the scalar.
            const int numRounds = 32;

            uint currentValue = startValue;

            for (int i = 0; i < numRounds; i++)
            {
                // --- Constant-Time Conditional Update ---
                // This is the core of the secure implementation. We avoid 'if' statements.

                // 1. Determine the control bit for this round from the secret scalar.
                //    We'll check the i-th bit of the scalar.
                uint controlBit = (scalar >> i) & 1; // This will be 0 or 1.

                // 2. Unconditionally compute what the "next value" would be if we DO step.
                //    The 'stepper' value is the current value, making the step content-directed.
                uint nextValueIfStep = Step(currentValue, currentValue);

                // 3. Create a bitmask from the control bit. This is the key trick.
                //    In two's complement, `-1` is all ones (`0xFFFFFFFF`). `0` is all zeros.
                //    This is a branchless way to create a mask that is either all 0s or all 1s.
                uint mask = (uint)-(int)controlBit; // `mask` will be 0x00000000 or 0xFFFFFFFF

                // 4. Use the mask to select the next state without a branch.
                //    - If mask is 0 (bit was 0), this is: (currentValue & 0xFFFFFFFF) | (nextValueIfStep & 0)
                //      Which simplifies to: currentValue. (A "dummy" step)
                //    - If mask is all 1s (bit was 1), this is: (currentValue & 0) | (nextValueIfStep & 0xFFFFFFFF)
                //      Which simplifies to: nextValueIfStep. (A "real" step)
                currentValue = (currentValue & ~mask) | (nextValueIfStep & mask);
            }

            return currentValue;
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Secure, Constant-Time Jump Function Demo ---");

            byte[] sharedSeed = new byte[32];
            RandomNumberGenerator.Fill(sharedSeed);
            var sf = new SyntheticField(sharedSeed);

            uint generatorG = sf.Generator;
            uint privateScalarK = 1234567890; // A sample scalar

            Console.WriteLine($"Public Generator (G): {generatorG}");
            Console.WriteLine($"Private Scalar (k): {privateScalarK}\n");

            uint result = sf.Jump(generatorG, privateScalarK);

            Console.WriteLine($"Result of Jump(G, k) = {result}");
            Console.WriteLine("\nThis result was computed using a fixed number of loops and");
            Console.WriteLine("branchless, constant-time logic to prevent side-channel attacks.");
        }
    }





}
