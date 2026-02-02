// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SFTrueContentDirected
    //          cd SFTrueContentDirected
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    public sealed class SyntheticCurve
    {
        private readonly uint[] _secretDomain;
        private readonly uint _generator;
        public uint Generator => _generator;

        // We no longer need a public or private 'Step' method.
        // The Jump function is now fully self-contained.

        public SyntheticCurve(ReadOnlySpan<byte> seed, int domainSize = 1024)
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
            ReadOnlySpan<byte> domainAsBytes = MemoryMarshal.AsBytes<uint>(_secretDomain);
            SHA256.HashData(domainAsBytes, hashOutput);
            uint generatorIndexSeed = MemoryMarshal.Read<uint>(hashOutput);
            int generatorIndex = (int)(generatorIndexSeed % (uint)domainSize);
            _generator = _secretDomain[generatorIndex];
        }

        /// <summary>
        /// A secure, one-way "jump" operation that is truly content-directed.
        /// Its evolution depends on the secret values within the domain.
        /// </summary>
        public uint Jump(uint startValue, uint scalar)
        {
            // The number of rounds is FIXED to prevent timing attacks.
            const int numRounds = 16; // A fixed number of mixing rounds.

            // 1. Initialize the internal state (the "walker").
            //    We hash the scalar to create a 32-byte initial state.
            Span<byte> walkerState = stackalloc byte[32];
            Span<byte> scalarBytes = stackalloc byte[sizeof(uint)];
            MemoryMarshal.Write(scalarBytes, ref scalar);
            SHA256.HashData(scalarBytes, walkerState);

            // 2. Find the starting index in our secret domain.
            int currentIndex = Array.BinarySearch(_secretDomain, startValue);
            if (currentIndex < 0)
            {
                // If the start value isn't in the domain, we must have a deterministic
                // fallback. Hashing it to get a starting index is a safe option.
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(MemoryMarshal.AsBytes(new ReadOnlySpan<uint>(ref startValue)), hash);
                currentIndex = (int)(MemoryMarshal.Read<uint>(hash) % (uint)_secretDomain.Length);
            }

            // 3. Perform the fixed number of rounds for the stateful hash walk.
            Span<byte> roundInput = stackalloc byte[walkerState.Length + sizeof(uint)];
            for (int i = 0; i < numRounds; i++)
            {
                // a. Get the secret content at the current location.
                uint domainValue = _secretDomain[currentIndex];

                // b. Combine the current walker state with the secret domain value.
                //    THIS IS THE CRITICAL CONTENT-DIRECTED STEP.
                walkerState.CopyTo(roundInput);
                MemoryMarshal.Write(roundInput.Slice(walkerState.Length), ref domainValue);

                // c. Hash to get the next state, which is also used to derive the next index.
                SHA256.HashData(roundInput, walkerState); // The state evolves.

                // d. The new index is derived from the new state.
                currentIndex = (int)(MemoryMarshal.Read<uint>(walkerState) % (uint)_secretDomain.Length);
            }

            // 4. The final result is the value at our destination.
            return _secretDomain[currentIndex];
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Fully Content-Directed, Secure Jump Function Demo ---");

            byte[] sharedSeed = new byte[32];
            RandomNumberGenerator.Fill(sharedSeed);
            var sc = new SyntheticCurve(sharedSeed);

            uint generatorG = sc.Generator;
            uint privateScalarK = 1234567890;

            Console.WriteLine($"Public Generator (G): {generatorG}");
            Console.WriteLine($"Private Scalar (k): {privateScalarK}\n");

            uint result = sc.Jump(generatorG, privateScalarK);

            Console.WriteLine($"Result of Jump(G, k) = {result}");
            Console.WriteLine("\nThis result was computed using a stateful hash walk.");
            Console.WriteLine("Each step of the walk was influenced by the actual secret numeric");
            Console.WriteLine("value at its current position, maximizing security.");
        }
    }






}
