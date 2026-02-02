// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Linq;
    using System.Numerics;
    using System.Security.Cryptography;
    using System.Text;

    // --- The Core Universe and its "Physics" ---

    public class ElccUniverse
    {
        private readonly int[] _stepRules;
        private readonly byte[] _terrainHash;
        public int TerrainSize { get; }

        public ElccUniverse(int size, int seed)
        {
            TerrainSize = size;
            _stepRules = new int[size];
            var random = new Random(seed);
            var positions = Enumerable.Range(0, size).ToList();
            for (int i = 0; i < size; i++)
            {
                int k = random.Next(positions.Count);
                _stepRules[i] = positions[k];
                positions.RemoveAt(k);
            }
            using var sha256 = SHA256.Create();
            _terrainHash = sha256.ComputeHash(_stepRules.SelectMany(BitConverter.GetBytes).ToArray());
        }

        public byte[] GetTerrainHash() => _terrainHash;
        private int Step(int currentPosition) => _stepRules[currentPosition];

        public int Jump(int startPosition, BigInteger instructionCount)
        {
            int currentPosition = startPosition;
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

    // --- The Components for the Signature Scheme ---
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
            Console.WriteLine($"\n  SIGNING the message: '{message}'");

            BigInteger b_echo_instruction = CreateEchoInstruction(message, PublicKey, _universe.GetTerrainHash());
            Console.WriteLine($"    1. Derived Echo Instruction 'b' for this message: {b_echo_instruction}");

            // THE CORRECT LOGIC: The total journey is (a + b) steps from Genesis.
            BigInteger masterInstruction = (_privateKey + b_echo_instruction);
            int signaturePoint = _universe.Jump(_universe.GetGenesisPoint(), masterInstruction);
            Console.WriteLine($"    2. Calculated the final Signature Point S = Jump(G, a+b): {signaturePoint}");

            return new Signature(signaturePoint);
        }

        public static BigInteger CreateEchoInstruction(string message, int publicKey, byte[] terrainHash)
        {
            using var sha256 = SHA256.Create();
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] publicKeyBytes = BitConverter.GetBytes(publicKey);
            byte[] dataToHash = new byte[messageBytes.Length + publicKeyBytes.Length + terrainHash.Length];
            Buffer.BlockCopy(publicKeyBytes, 0, dataToHash, 0, publicKeyBytes.Length);
            Buffer.BlockCopy(messageBytes, 0, dataToHash, publicKeyBytes.Length, messageBytes.Length);
            Buffer.BlockCopy(terrainHash, 0, dataToHash, publicKeyBytes.Length + messageBytes.Length, terrainHash.Length);
            byte[] hash = sha256.ComputeHash(dataToHash);
            return new BigInteger(hash, isUnsigned: true);
        }
    }

    public static class Verifier
    {
        public static bool Verify(ElccUniverse universe, int signerPublicKey, string message, Signature signature)
        {
            Console.WriteLine($"\n  VERIFYING signature for message: '{message}' from signer with Public Key {signerPublicKey}");

            BigInteger b_echo_instruction = ElccUser.CreateEchoInstruction(message, signerPublicKey, universe.GetTerrainHash());
            Console.WriteLine($"    1. Verifier re-derived Echo Instruction 'b': {b_echo_instruction}");

            // The verifier's journey is (a steps) then (b steps).
            // They start at 'A' (which is already 'a' steps from G) and take 'b' more steps.
            int expectedSignaturePoint = universe.Jump(signerPublicKey, b_echo_instruction);
            Console.WriteLine($"    2. Verifier calculates Expected Point = Jump(A, b): {expectedSignaturePoint}");

            bool isValid = signature.FinalRendezvousPoint == expectedSignaturePoint;
            Console.WriteLine($"    3. Comparing Signature ({signature.FinalRendezvousPoint}) with Expected Point ({expectedSignaturePoint})");

            return isValid;
        }
    }

    // --- Main Program ---
    public static class Program
    {
        public static void Main()
        {
            int sharedSeed = 12345;
            var universe = new ElccUniverse(size: 257, seed: sharedSeed);
            var alice = new ElccUser(universe);
            Console.WriteLine($"Alice has joined the universe. Her Public Key is: {alice.PublicKey}");

            string originalMessage = "The launch codes are 00-00-00";
            Signature signature = alice.Sign(originalMessage);

            Console.WriteLine("\n--- A member of the trusted group now verifies the signature ---");

            // Test 1
            bool isAuthentic = Verifier.Verify(universe, alice.PublicKey, originalMessage, signature);
            Console.WriteLine("\nTest 1: Verifying the ORIGINAL message...");
            if (isAuthentic) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine(">>> RESULT: SIGNATURE IS VALID!"); }
            else { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(">>> RESULT: SIGNATURE IS INVALID!"); }
            Console.ResetColor();

            // Test 2
            string tamperedMessage = "The launch codes are 11-11-11";
            bool isTamperedAuthentic = Verifier.Verify(universe, alice.PublicKey, tamperedMessage, signature);
            Console.WriteLine("\nTest 2: Verifying a TAMPERED message with the SAME signature...");
            if (!isTamperedAuthentic) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine(">>> RESULT: SIGNATURE IS CORRECTLY IDENTIFIED AS INVALID!"); }
            else { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(">>> FAILED to detect tampering."); }
            Console.ResetColor();
        }
    }
}