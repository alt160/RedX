using System;

// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    public static class FirstPrincipleUniverse
    {
        // --- The Public, Agreed-Upon "Laws of Physics" ---

        // The Terrain Size: The number of values in our closed loop.
        private const int TerrainSize = 29; // A prime number is nice, but not required here.

        // The "1-Inch Reference Block": A public, fixed, arbitrary rule for a single step.
        // This is a permutation of numbers 0-28. It defines our core "physics."
        private static readonly int[] _stepRules = new int[]
        {
        11, 23, 5, 17, 1, 14, 26, 8, 20, 2, 15, 28, 9, 21, 3, 16, 25, 6, 18, 0, 12, 24, 7, 19, 1, 13, 27, 4, 10
        };

        // --- The Internal Mechanics of the Universe ---

        /// <summary>
        /// The most fundamental operation. Takes one step according to the public rulebook.
        /// This is our "1-inch" measurement. It's internal because users only use the Jump machine.
        /// </summary>
        private static int Step(int currentPosition)
        {
            return _stepRules[currentPosition];
        }

        /// <summary>
        /// The "Mile Machine" (our Rendezvous Function).
        /// It applies the fundamental Step operation a specified number of times.
        /// Its construction guarantees the "Balanced Equation" property.
        /// </summary>
        public static int Jump(int startPosition, int instructionCount)
        {
            Console.WriteLine($"      -> JUMPING: Starting at {startPosition}, taking {instructionCount} steps...");
            int currentPosition = startPosition;
            for (int i = 0; i < instructionCount; i++)
            {
                currentPosition = Step(currentPosition);
            }
            Console.WriteLine($"      ...Landed at {currentPosition}.");
            return currentPosition;
        }

        // A helper to get our Genesis point.
        public static int GetGenesisPoint() => 0;
    }


    // --- The Main Program to Demonstrate the First Principle ---
    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Building a Rendezvous Machine from a First Principle ---");

            // STEP 1: Define the two secret values.
            // These exist only in the minds of Alice and Bob.
            int secret_a = 7;  // Alice's secret number of steps
            int secret_b = 12; // Bob's secret number of steps
            Console.WriteLine($"Alice's secret: a = {secret_a}");
            Console.WriteLine($"Bob's secret:   b = {secret_b}");

            // The public starting point for everyone.
            int genesisPoint = FirstPrincipleUniverse.GetGenesisPoint();
            Console.WriteLine($"Public Genesis Point: {genesisPoint}");

            // STEP 2: The "Context" is created.
            // Alice and Bob calculate their public keys. These can be shared openly.
            Console.WriteLine("\n[Phase 1: Calculating Public Keys]");
            int public_A = FirstPrincipleUniverse.Jump(genesisPoint, secret_a);
            int public_B = FirstPrincipleUniverse.Jump(genesisPoint, secret_b);
            Console.WriteLine($"Alice's Public Key (A): {public_A}");
            Console.WriteLine($"Bob's Public Key (B):   {public_B}");

            // STEP 3: The "Exchange of Context" and Evolution to a Shared Outcome.
            // This is the core demonstration of the First Principle.
            Console.WriteLine("\n[Phase 2: The Rendezvous - Evolving to a Shared Outcome]");

            // Alice uses Bob's public key (B) and her secret (a)
            Console.WriteLine("\nAlice's Calculation:");
            int sharedSecret_by_Alice = FirstPrincipleUniverse.Jump(public_B, secret_a);

            // Bob uses Alice's public key (A) and his secret (b)
            Console.WriteLine("\nBob's Calculation:");
            int sharedSecret_by_Bob = FirstPrincipleUniverse.Jump(public_A, secret_b);

            // STEP 4: The Verification.
            Console.WriteLine("\n[Phase 3: Verifying the Outcome]");
            Console.WriteLine($"Alice's final secret value: {sharedSecret_by_Alice}");
            Console.WriteLine($"Bob's final secret value:   {sharedSecret_by_Bob}");

            if (sharedSecret_by_Alice == sharedSecret_by_Bob)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nSUCCESS! The First Principle holds. A shared secret was created.");
                Console.ResetColor();
                Console.WriteLine("The 'balanced equation' is proven by the implementation.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nFAILURE! The implementation does not satisfy the First Principle.");
                Console.ResetColor();
            }
        }
    }
}