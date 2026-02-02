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

    public record Signature(int FinalRendezvousPoint);

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
            BigInteger b_echo_instruction = CreateEchoInstruction(message, PublicKey, _universe.TerrainSize); // Pass size as a proxy for terrain hash
            BigInteger masterInstruction = (_privateKey + b_echo_instruction);
            int signaturePoint = _universe.Jump(_universe.GetGenesisPoint(), masterInstruction);
            return new Signature(signaturePoint);
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
        public static bool Verify(ElccUniverse universe, int signerPublicKey, string message, Signature signature)
        {
            BigInteger b_echo_instruction = ElccUser.CreateEchoInstruction(message, signerPublicKey, universe.TerrainSize);
            int expectedSignaturePoint = universe.Jump(signerPublicKey, b_echo_instruction);
            return signature.FinalRendezvousPoint == expectedSignaturePoint;
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

            Console.WriteLine($"Signature created: {signature.FinalRendezvousPoint}");

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