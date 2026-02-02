// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Linq;

    // This class represents our synthetic universe. It contains the public "Laws of Physics."
    public class FirstPrincipleUniverse
    {
        // The "Terrain" is now a shared secret, generated from a seed.
        private readonly int[] _stepRules; // The chaotic road map.
        public int TerrainSize { get; }

        public FirstPrincipleUniverse(int size, int seed)
        {
            TerrainSize = size;
            _stepRules = new int[size];
            var random = new Random(seed);

            // Generate a fixed but random-looking permutation for our "Step" rule.
            var positions = Enumerable.Range(0, size).ToList();
            for (int i = 0; i < size; i++)
            {
                int k = random.Next(positions.Count);
                _stepRules[i] = positions[k];
                positions.RemoveAt(k);
            }
        }

        // --- The Public Mechanics ---

        /// <summary>
        /// The most fundamental operation. Takes one step according to the secret terrain's rules.
        /// </summary>
        private int Step(int currentPosition)
        {
            return _stepRules[currentPosition];
        }

        /// <summary>
        /// The "Mile Machine" (our Rendezvous Function).
        /// It applies the fundamental Step operation a specified number of times.
        /// Its construction guarantees the "Balanced Equation" property.
        /// </summary>
        public int Jump(int startPosition, int instructionCount)
        {
            int currentPosition = startPosition;
            for (int i = 0; i < instructionCount; i++)
            {
                currentPosition = Step(currentPosition);
            }
            return currentPosition;
        }

        public int GetGenesisPoint() => 0;
    }


    // --- The Main Program to Demonstrate the First Principle ---
    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- The Final 'Secret Terrain' Key Exchange (Corrected) ---");

            // STEP 1: Alice and Bob secretly agree on a seed for their universe.
            int sharedSeed = 42;
            Console.WriteLine($"[1] Pre-shared secret seed: {sharedSeed}");

            // This creates a universe with a secret, chaotic road map.
            var universe = new FirstPrincipleUniverse(size: 257, seed: sharedSeed);
            Console.WriteLine("    A secret terrain (rulebook) has been generated from the seed.");

            // STEP 2: Alice and Bob choose their private keys (secret instructions).
            int secret_a = 101; // Alice's secret number of steps
            int secret_b = 179; // Bob's secret number of steps
            Console.WriteLine($"\n[2] Alice's private key: a = {secret_a}");
            Console.WriteLine($"    Bob's private key:   b = {secret_b}");

            int genesisPoint = universe.GetGenesisPoint();

            // STEP 3: They calculate their PUBLIC keys and exchange them.
            Console.WriteLine("\n[3] Calculating and Exchanging Public Keys (The 'Context')...");
            int public_A = universe.Jump(genesisPoint, secret_a);
            int public_B = universe.Jump(genesisPoint, secret_b);
            Console.WriteLine($"    Alice's Public Key (A): {public_A}");
            Console.WriteLine($"    Bob's Public Key (B):   {public_B}");

            // STEP 4: The Rendezvous - The correct "Exchange of Context."
            Console.WriteLine("\n[4] Evolving to a Shared Outcome...");

            // Alice uses Bob's PUBLIC key (B) and her PRIVATE key (a).
            Console.WriteLine("    Alice uses B and her secret a...");
            int sharedSecret_by_Alice = universe.Jump(public_B, secret_a);
            Console.WriteLine($"    ...Alice arrives at shared secret position: {sharedSecret_by_Alice}");

            // Bob uses Alice's PUBLIC key (A) and his PRIVATE key (b).
            Console.WriteLine("    Bob uses A and his secret b...");
            int sharedSecret_by_Bob = universe.Jump(public_A, secret_b);
            Console.WriteLine($"    ...Bob arrives at shared secret position:   {sharedSecret_by_Bob}");

            // STEP 5: Verification.
            Console.WriteLine("\n[5] Verifying the Outcome...");
            if (sharedSecret_by_Alice == sharedSecret_by_Bob)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("    SUCCESS! The First Principle holds. The journeys converged.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("    FAILURE! The implementation does not satisfy the First Principle.");
            }
            Console.ResetColor();
        }
    }
}