// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Numerics;
    using System.Security.Cryptography;
    using System.Text;

    // --- The Core Universe and its "Physics" ---

    public class ElccUniverse
    {
        // The Terrain now holds rich, secret 64-bit values.
        private readonly ulong[] _terrainValues;
        public int TerrainSize => _terrainValues.Length;

        public ElccUniverse(int size, int seed)
        {
            // --- UPGRADE 1: Generate a terrain of rich, unique 64-bit values ---
            _terrainValues = new ulong[size];
            var random = new Random(seed);
            var usedValues = new HashSet<ulong>(); // To ensure no repeats

            for (int i = 0; i < size; i++)
            {
                ulong randomValue;
                byte[] buffer = new byte[8]; // 8 bytes for a 64-bit ulong
                do
                {
                    random.NextBytes(buffer);
                    randomValue = BitConverter.ToUInt64(buffer, 0);
                } while (usedValues.Contains(randomValue)); // Ensure no duplicate values

                _terrainValues[i] = randomValue;
                usedValues.Add(randomValue);
            }
        }

        // This is now the fundamental operation. It's a complex, "alchemical" step.
        private int Step(int currentPosition)
        {
            // --- UPGRADE 2: The "Physics" are now value-dependent ---
            ulong currentValue = _terrainValues[currentPosition];

            // Let's create a simple but non-linear rule based on the value's properties.
            // The step distance depends on the number of set bits and some low-order bits.
            int bitCount = BitOperations.PopCount(currentValue);
            int lowBits = (int)(currentValue & 0b1111); // Use the last 4 bits

            int stepAmount = (bitCount + lowBits + 1); // +1 to ensure we always move

            return (currentPosition + stepAmount) % TerrainSize;
        }

        public int Jump(int startPosition, BigInteger instructionCount)
        {
            int currentPosition = startPosition;
            // The core engine remains the same simple, provable loop.
            BigInteger effectiveSteps = instructionCount % new BigInteger(TerrainSize);
            if (effectiveSteps < 0) effectiveSteps += TerrainSize;

            for (BigInteger i = 0; i < effectiveSteps; i++)
            {
                currentPosition = Step(currentPosition);
            }
            return currentPosition;
        }
        public int GetGenesisPoint() => 0;
    }


    // --- The rest of the program (Signature, ElccUser, Verifier, Main) remains IDENTICAL ---
    // No changes are needed because we designed it to be agnostic to the underlying physics!

    public record Signature(int R, BigInteger S);


    public class ElccUser
    {
        private readonly ElccUniverse _universe;
        private readonly BigInteger _privateKey;
        public int PublicKey { get; }

        public ElccUser(ElccUniverse universe)
        {
            _universe = universe;
            byte[] randomBytes = new byte[16];
            new Random().NextBytes(randomBytes);
            _privateKey = new BigInteger(randomBytes, isUnsigned: true);
            PublicKey = _universe.Jump(_universe.GetGenesisPoint(), _privateKey);
        }

        public Signature Sign(string message)
        {
            // 1) Ephemeral secret
            BigInteger k = BigIntegerExtensions.RandomBigInteger(_universe.TerrainSize);
            int R = _universe.Jump(0, k);

            // 2) Challenge binds R, Pub and message
            BigInteger c = CreateEchoInstruction($"{message}:{R}", PublicKey, _universe.TerrainSize);

            // 3) Response combines ephemeral + priv×challenge
            BigInteger s = k + (_privateKey * c);

            return new Signature(R, s);
        }
        public static BigInteger CreateEchoInstruction(string message, int publicKey, int terrainSize)
        {
            using var sha256 = SHA256.Create();
            string dataToHash = $"{message}:{publicKey}:{terrainSize}";
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));
            return new BigInteger(hash, isUnsigned: true);
        }
    }

    public static class Verifier
    {
        public static bool Verify(
            ElccUniverse universe,
            int signerPublicKey,
            string message,
            Signature sig)
        {
            // Recompute challenge
            BigInteger c = ElccUser.CreateEchoInstruction(
                $"{message}:{sig.R}",
                signerPublicKey,
                universe.TerrainSize);

            // Convergence test: Jump(0, s) == Jump(R, c)
            int lhs = universe.Jump(0, sig.S);
            int rhs = universe.Jump(sig.R, c);
            return lhs == rhs;
        }
    }

    public static class BigIntegerExtensions
    {
        /// <summary>
        /// Returns a cryptographically-secure random BigInteger in [0, maxExclusive).
        /// </summary>
        public static BigInteger RandomBigInteger(BigInteger maxExclusive)
        {
            if (maxExclusive.Sign <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxExclusive), "maxExclusive must be positive.");

            // Determine how many bytes we need
            int byteLen = (int)Math.Ceiling(BigInteger.Log(maxExclusive, 2) / 8);
            using var rng = RandomNumberGenerator.Create();

            while (true)
            {
                byte[] data = new byte[byteLen + 1];       // +1 to ensure the sign bit is zero
                rng.GetBytes(data);
                data[^1] &= 0x7F;                          // clear highest bit to keep value non-negative

                var candidate = new BigInteger(data);      // little-endian two’s-complement
                if (candidate < maxExclusive)
                    return candidate;
            }
        }
    }

    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- ELCC Signature with True 'Secret Terrain' ---");

            int sharedSeed = 654321;
            var universe = new ElccUniverse(size: 257, seed: sharedSeed);
            var alice = new ElccUser(universe);

            Console.WriteLine($"Alice's Public Key: {alice.PublicKey}");

            string originalMessage = "The terrain itself is now part of the secret";
            Signature signature = alice.Sign(originalMessage);

            Console.WriteLine($"Signature created: {signature.R}");

            bool isAuthentic = Verifier.Verify(universe, alice.PublicKey, originalMessage, signature);

            Console.WriteLine("\nVerifying the ORIGINAL message...");
            if (isAuthentic) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine(">>> RESULT: SIGNATURE IS VALID!"); }
            else { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(">>> RESULT: SIGNATURE IS INVALID!"); }
            Console.ResetColor();

            string tamperedMessage = "The terrain itself is NOT part of the secret";
            bool isTamperedAuthentic = Verifier.Verify(universe, alice.PublicKey, tamperedMessage, signature);

            Console.WriteLine("\nVerifying a TAMPERED message...");
            if (!isTamperedAuthentic) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine(">>> RESULT: SIGNATURE IS CORRECTLY IDENTIFIED AS INVALID!"); }
            else { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(">>> FAILED to detect tampering."); }
            Console.ResetColor();
        }
    }
}