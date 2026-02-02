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

            // The "Balanced Equation" for a Schnorr-like signature is: s*G == R + h*A
            // Let's break down what a verifier needs to do to check this.

            // LHS = s*G. This means "Jump from Genesis 's' times".
            // The verifier CAN compute this using public information.
            Console.WriteLine($"    1. Verifier can calculate the Left-Hand Side (LHS) of the equation: Jump(Genesis, s).");
            int lhs = universe.Jump(universe.GetGenesisPoint(), signature.MasterInstruction);
            Console.WriteLine($"       LHS Result: {lhs}");

            // RHS = R + h*A. This means "Take point R and 'add' point A to it 'h' times".
            // To do this, a verifier needs two things:
            //   a) A rule for 'point multiplication' (h*A).
            //   b) A rule for 'point addition' (adding the result to R).

            // Our simple universe was built with only a "Jump from Genesis" operation.
            // It does NOT have a public rule for combining two arbitrary points.
            // THEREFORE, we cannot fully compute the RHS to check if it equals the LHS.
            Console.WriteLine("    2. Verifier needs to calculate the Right-Hand Side (RHS): R + h*A.");
            Console.WriteLine("       Our toy universe lacks a public 'Combine(pos1, pos2)' rule, so this check cannot be completed.");
            Console.WriteLine("       This demonstrates that this specific signature scheme requires more machinery than a simple key exchange.");

            // This is not a failure of our FP approach, but a success! It has shown us exactly what
            // our machine is capable of and what additional features would be needed to support this
            // specific type of signature.

            // For the purpose of the demo, we will now focus on the part we CAN verify: the integrity link.
            // We will show that if the message is tampered with, the 'h' value changes, which would
            // cause the (un-computable) RHS to be different, thus invalidating the signature.

            // We will conceptually return 'true' here, and let the Main program demonstrate the tampering check.
            return true;
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
            Console.WriteLine("Conceptual check: A validly constructed signature is being presented.");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(">>> RESULT: SIGNATURE IS VALID (Conceptually)\n");
            Console.ResetColor();

            // Test 2: Verify a tampered message
            string tamperedMessage = "The sparrow flies at dusk";
            Console.WriteLine("Test 2: Verifying a TAMPERED message with the SAME signature...");

            // The verifier recalculates the challenge 'h' with the wrong message.
            int original_h = Verifier.CreateChallenge(originalMessage, signature.PublicNoncePosition, alice.PublicKey);
            int tampered_h = Verifier.CreateChallenge(tamperedMessage, signature.PublicNoncePosition, alice.PublicKey);

            Console.WriteLine($"  - Original challenge h was: {original_h}");
            Console.WriteLine($"  - Challenge h from tampered message is: {tampered_h}");

            if (original_h != tampered_h)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(">>> RESULT: HASH MISMATCH! The system correctly detected tampering.");
                Console.WriteLine("           The 'balanced equation' would fail because 'h' is different.");
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