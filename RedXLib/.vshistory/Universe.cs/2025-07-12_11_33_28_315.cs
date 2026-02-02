// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    // --- The Core Universe (Unchanged from our last version) ---
    public class FirstPrincipleUniverse
    {
        private readonly int[] _stepRules;
        public int TerrainSize { get; }

        /// <summary>
        /// The public "Point Addition" rule for our universe.
        /// It combines two arbitrary positions into a third in a chaotic but deterministic way.
        /// </summary>
        public int Combine(int positionA, int positionB)
        {
            // 1. Get the secret values from the terrain.
            long valueA = _stepRules[positionA]; // In our simple model, the step rule is the value
            long valueB = _stepRules[positionB];

            // 2. Mix them together using a public recipe (hashing).
            using var sha256 = SHA256.Create();
            string dataToHash = $"{valueA}:{valueB}";
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));

            // 3. Convert the hash to a number and map it to a valid position.
            long hashAsLong = Math.Abs(BitConverter.ToInt64(bytes, 0));

            return (int)(hashAsLong % TerrainSize);
        }


        public FirstPrincipleUniverse(int size, int seed)
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
        }

        private int Step(int currentPosition) => _stepRules[currentPosition];

        public int Jump(int startPosition, int instructionCount)
        {
            int currentPosition = startPosition;
            // Use modulo to keep instructionCount within a reasonable computational bound
            // while preserving the algebraic properties for our toy.
            int effectiveSteps = instructionCount % (TerrainSize * 2); // Avoid excessive looping
            for (int i = 0; i < Math.Abs(effectiveSteps); i++)
            {
                currentPosition = Step(currentPosition);
            }
            return currentPosition;
        }

        public int GetGenesisPoint() => 0;
    }


    // --- New Components for the Signature Scheme ---

    // A simple record to hold the two parts of our signature.
    public record Signature(int PublicNoncePosition, int MasterInstruction);

    // Represents a user who can sign messages.
    public class Signer
    {
        private readonly FirstPrincipleUniverse _universe;
        private readonly int _privateKey; // This is secret 'a'.

        public int PublicKey { get; } // This is public 'A'.

        public Signer(FirstPrincipleUniverse universe)
        {
            _universe = universe;
            // Generate a private key (a random instruction)
            _privateKey = new Random().Next(1, universe.TerrainSize);
            // Calculate the corresponding public key
            PublicKey = _universe.Jump(universe.GetGenesisPoint(), _privateKey);
        }

        public Signature Sign(string message)
        {
            Console.WriteLine($"\n  ALICE IS SIGNING THE MESSAGE: '{message}'");

            // 1. The One-Time Secret (Nonce): Generate a new secret instruction 'r' for this signature only.
            int r_nonce = new Random().Next(1, _universe.TerrainSize);
            Console.WriteLine($"    1. Generated a one-time secret nonce 'r': {r_nonce}");

            // 2. Calculate the public part of the nonce, R.
            int R_publicNoncePos = _universe.Jump(_universe.GetGenesisPoint(), r_nonce);
            Console.WriteLine($"    2. Calculated the public part of the nonce 'R' (a position): {R_publicNoncePos}");

            // 3. The Public Challenge: Hash the message and the public nonce R to create 'h'.
            // This binds the signature to the message content.
            int h_challenge = Verifier.CreateChallenge(message, R_publicNoncePos, this.PublicKey);
            Console.WriteLine($"    3. Created a public challenge 'h' from the message and public keys: {h_challenge}");

            // 4. The Master Instruction: Combine secrets 'a' and 'r' with the public challenge 'h'.
            // The formula is s = r + h * a. This is algebra on the instructions, not on the terrain.
            // We use modulo arithmetic to keep the numbers within the group order.
            long s_masterInstruction = ((long)r_nonce + (long)h_challenge * _privateKey) % _universe.TerrainSize;
            Console.WriteLine($"    4. Calculated the master instruction 's' = (r + h*a): {s_masterInstruction}");

            // 5. The final signature is the pair (R, s).
            return new Signature(R_publicNoncePos, (int)s_masterInstruction);
        }
    }

    // A static class for verification, as anyone can do it with public info.
    // A static class for verification, as anyone can do it with public info.
    public static class Verifier
    {
        // This is our public hash function. It's not cryptographically secure, but demonstrates the principle.
        public static int CreateChallenge(string message, int publicNoncePos, int publicKey)
        {
            using var sha256 = SHA256.Create();
            string dataToHash = $"{message}:{publicNoncePos}:{publicKey}";
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));
            // Turn the big hash into a small integer for our toy universe.
            return Math.Abs(BitConverter.ToInt32(bytes, 0) % 1000); // A small, deterministic challenge number
        }

        public static bool Verify(FirstPrincipleUniverse universe, int signerPublicKey, string message, Signature signature)
        {
            Console.WriteLine($"\n  A VERIFIER IS CHECKING THE SIGNATURE for message: '{message}'");

            // The "Balanced Equation" is: s*G == R + h*A
            // We can now compute both sides!

            // 1. Calculate the Left-Hand Side (LHS): s*G
            // This is "Jump from Genesis 's' times".
            int lhs = universe.Jump(universe.GetGenesisPoint(), signature.MasterInstruction);
            Console.WriteLine($"    1. Calculated LHS (s*G): {lhs}");

            // 2. Calculate the Right-Hand Side (RHS): R + h*A
            // This is a more complex journey: "a journey of 'h' multiplications of A, combined with R".

            // First, we need to re-calculate the challenge 'h' to ensure the message wasn't tampered with.
            int h_challenge = CreateChallenge(message, signature.PublicNoncePosition, signerPublicKey);

            // Next, we calculate the position for the h*A part of the journey.
            // This means "start at the signer's public key (A) and Jump with instruction 'h'".
            // NOTE: This is a simplification. A real ECC group has a different 'point multiplication' rule.
            // But for our universe, this is a valid and consistent way to define it.
            int pos_hA = universe.Jump(signerPublicKey, h_challenge);
            Console.WriteLine($"    2. Calculated intermediate position for h*A: {pos_hA}");

            // Finally, we use our new Combine function to 'add' R to the result of h*A.
            // R is the public nonce position from the signature.
            int rhs = universe.Combine(signature.PublicNoncePosition, pos_hA);
            Console.WriteLine($"    3. Calculated RHS (R + h*A) using Combine function: {rhs}");

            // 4. The final check: Do the two separate journeys land on the same spot?
            return lhs == rhs;
        }

    }


    // --- Main Demonstration Program ---
    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Signature Scheme Toy Model ---");

            var universe = new FirstPrincipleUniverse(size: 257, seed: 66);
            var alice = new Signer(universe);

            Console.WriteLine($"\nAlice's Public Key is: {alice.PublicKey}");

            string originalMessage = "The eagle flies at dawn";
            Signature signature = alice.Sign(originalMessage);

            Console.WriteLine($"\nSignature created: R={signature.PublicNoncePosition}, s={signature.MasterInstruction}");

            // --- Verification ---
            Console.WriteLine("\n--- VERIFICATION STEP ---");

            // Test 1: Verify the authentic message
            bool isAuthentic = Verifier.Verify(universe, alice.PublicKey, originalMessage, signature);
            Console.WriteLine("\nTest 1: Verifying the ORIGINAL message...");
            if (isAuthentic)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(">>> RESULT: SIGNATURE IS VALID! The balanced equation holds.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(">>> RESULT: SIGNATURE IS INVALID!");
            }
            Console.ResetColor();


            // Test 2: Verify a tampered message
            string tamperedMessage = "The sparrow flies at dusk";
            bool isTamperedAuthentic = Verifier.Verify(universe, alice.PublicKey, tamperedMessage, signature);
            Console.WriteLine("\nTest 2: Verifying a TAMPERED message with the SAME signature...");
            if (!isTamperedAuthentic)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(">>> RESULT: SIGNATURE IS CORRECTLY IDENTIFIED AS INVALID!");
                Console.WriteLine("           The balanced equation failed because the tampered 'h' led to a different RHS.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(">>> FAILED to detect tampering.");
            }
            Console.ResetColor();
        }
    }
}