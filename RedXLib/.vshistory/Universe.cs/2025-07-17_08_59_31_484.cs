// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    // To run this, create a new C# console project and paste this code into Program.cs
    // Example: dotnet new console -o SFHolistic
    //          cd SFHolistic
    //          (paste code into Program.cs)
    //          dotnet run

    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    public sealed class SyntheticField
    {
        private readonly uint[] _secretDomain;

        // The Generator is now a private field, calculated once at initialization.
        private readonly uint _generator;

        // The public property exposes the calculated Generator.
        public uint Generator => _generator;

        public SyntheticField(ReadOnlySpan<byte> seed, int domainSize = 1024)
        {
            if (seed.Length != 32) throw new ArgumentException("Seed must be 32 bytes.");
            _secretDomain = new uint[domainSize];

            // --- Step 1: Populate the domain from the seed (unchanged) ---
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

            // ---------- MODIFIED SECTION START ----------

            // --- Step 2: Holistically derive the Generator ---
            // We will hash the *entire* secret domain to get a seed for our generator's index.
            // This makes the generator a property of the whole secret state.

            // To hash the domain, we treat the uint[] array as a byte array.
            // This is a highly efficient, zero-copy conversion.
            ReadOnlySpan<byte> domainAsBytes = MemoryMarshal.AsBytes<uint>(_secretDomain);

            // Hash the byte representation of the domain.
            SHA256.HashData(domainAsBytes, hashOutput);

            // Use the resulting hash to deterministically select an index.
            // The attacker cannot predict this index without knowing the entire domain.
            uint generatorIndexSeed = MemoryMarshal.Read<uint>(hashOutput);
            int generatorIndex = (int)(generatorIndexSeed % (uint)domainSize);

            // Set the private generator field to the value at the derived index.
            _generator = _secretDomain[generatorIndex];

            Console.WriteLine($"SF Initialized. Generator index derived holistically: {generatorIndex}.");

            // ---------- MODIFIED SECTION END ----------
        }

        // Step and Jump methods remain unchanged. They are consumers of the Generator,
        // but their internal logic does not need to be modified.
        public uint Step(uint valueA, uint valueB)
        {
            if (valueA > valueB) (valueA, valueB) = (valueB, valueA);
            int indexA = Array.BinarySearch(_secretDomain, valueA);
            int indexB = Array.BinarySearch(_secretDomain, valueB);
            if (indexA < 0 || indexB < 0)
            {
                Span<byte> buffer = stackalloc byte[sizeof(uint) * 2];
                MemoryMarshal.Write(buffer, ref valueA);
                MemoryMarshal.Write(buffer.Slice(sizeof(uint)), ref valueB);
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(buffer, hash);
                return MemoryMarshal.Read<uint>(hash);
            }
            uint newIndex = ((uint)indexA + (uint)indexB) % (uint)_secretDomain.Length;
            return _secretDomain[newIndex];
        }

        public uint Jump(uint startValue, uint scalar)
        {
            uint numSteps = (scalar % 8) + 1;
            uint currentValue = startValue;
            uint stepValue = scalar;
            for (int i = 0; i < numSteps; i++)
            {
                uint nextValue = Step(currentValue, stepValue);
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
            Console.WriteLine("--- Demonstrating Holistic Generator Derivation ---");

            // --- Setup ---
            byte[] sharedSeed = new byte[32];
            RandomNumberGenerator.Fill(sharedSeed);
            var sf = new SyntheticField(sharedSeed);

            // --- Demonstration ---
            // We get the Generator via the public property.
            // We no longer assume it's the element at index 0.
            uint generatorG = sf.Generator;
            Console.WriteLine($"\nPublic Generator (G) is: {generatorG}");
            Console.WriteLine("This value is no longer guaranteed to be the smallest in the secret domain.");

            // Generate a random scalar as before.
            Span<byte> randomBytes = stackalloc byte[sizeof(uint)];
            RandomNumberGenerator.Fill(randomBytes);
            uint privateScalarK = MemoryMarshal.Read<uint>(randomBytes);
            Console.WriteLine($"Private Random Scalar (k): {privateScalarK}\n");

            // The Jump operation works exactly the same.
            uint result = sf.Jump(generatorG, privateScalarK);
            Console.WriteLine($"Resulting 'Random' Domain Value = Jump(G, k)");
            Console.WriteLine($" -> {result}");

            Console.WriteLine("\nCONCLUSION: The primitive now has a hardened, unpredictable starting point,");
            Console.WriteLine("preventing attacks based on the generator being a statistical special case.");
        }
    }



}
