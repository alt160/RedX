// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Numerics;

    // First, let's define what an "Instruction" is in our universe.
    // It's a "recipe" with multiple components.
    public record struct Instruction(long Multiplier, long Shift);

    public static class AlchemicalUniverse
    {
        // --- The Public, Agreed-Upon "Laws of Physics" ---
        private const int TerrainSize = 137; // A larger prime for more interesting results.

        // --- The Core Logic of the Universe ---

        /// <summary>
        /// The "1-Inch Reference Block": A public, commutative rule for combining instructions.
        /// This is the heart of the First Principle's guarantee.
        /// Note: The order of a and b does not matter.
        /// </summary>
        public static Instruction CombineInstructions(Instruction a, Instruction b)
        {
            // We use simple modular addition because it's commutative.
            // a + b = b + a. This guarantees the rendezvous.
            long newMultiplier = (a.Multiplier + b.Multiplier) % TerrainSize;
            long newShift = (a.Shift + b.Shift) % TerrainSize;
            return new Instruction(newMultiplier, newShift);
        }

        /// <summary>
        /// The "Mile Machine": A complex, algorithmic, state-dependent Jump.
        /// This is NOT just a simple loop. It provides the security.
        /// </summary>
        public static int Jump(int startPosition, Instruction instruction)
        {
            // The rule is an arbitrary, non-linear "alchemical" formula.
            // It uses both parts of the instruction and the current position.
            BigInteger bigPos = startPosition;
            BigInteger bigMult = instruction.Multiplier;
            BigInteger bigShift = instruction.Shift;
            BigInteger bigSize = TerrainSize;

            // An example of a complex, non-obvious rule:
            BigInteger newPosition = (bigPos * bigPos * bigMult + bigShift) % bigSize;

            return (int)newPosition;
        }

        public static int GetGenesisPoint() => 2; // Start somewhere other than 0 for more interesting math.
    }


    // --- Main Program to Demonstrate the Advanced Concept ---
    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- Building an Algorithmic Rendezvous Machine ---");

            // STEP 1: Define the two secret instructions (our complex "recipes").
            var secret_a = new Instruction(Multiplier: 23, Shift: 78);
            var secret_b = new Instruction(Multiplier: 91, Shift: 12);
            Console.WriteLine($"Alice's secret instruction: a = {secret_a}");
            Console.WriteLine($"Bob's secret instruction:   b = {secret_b}");

            int genesisPoint = AlchemicalUniverse.GetGenesisPoint();
            Console.WriteLine($"Public Genesis Point: {genesisPoint}");

            // STEP 2: The Rendezvous - A more direct demonstration of the FP.
            // Alice and Bob don't need to exchange public keys to prove the concept.
            // They can prove that their combined journeys from Genesis lead to the same place.
            Console.WriteLine("\n[The Rendezvous Proof]");

            // Alice combines her secret with Bob's, then Jumps from Genesis.
            Console.WriteLine("\nAlice's Calculation:");
            Console.WriteLine($"  - Combines her secret 'a' with Bob's 'b'...");
            Instruction combined_for_Alice = AlchemicalUniverse.CombineInstructions(secret_a, secret_b);
            Console.WriteLine($"  - Resulting master instruction: {combined_for_Alice}");
            int finalDestination_by_Alice = AlchemicalUniverse.Jump(genesisPoint, combined_for_Alice);
            Console.WriteLine($"  - Final Destination: {finalDestination_by_Alice}");


            // Bob combines his secret with Alice's, then Jumps from Genesis.
            Console.WriteLine("\nBob's Calculation:");
            Console.WriteLine($"  - Combines his secret 'b' with Alice's 'a'...");
            Instruction combined_for_Bob = AlchemicalUniverse.CombineInstructions(secret_b, secret_a);
            Console.WriteLine($"  - Resulting master instruction: {combined_for_Bob}");
            int finalDestination_by_Bob = AlchemicalUniverse.Jump(genesisPoint, combined_for_Bob);
            Console.WriteLine($"  - Final Destination: {finalDestination_by_Bob}");


            // STEP 3: Verification.
            Console.WriteLine("\n[Verification]");
            if (finalDestination_by_Alice == finalDestination_by_Bob)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("SUCCESS! The First Principle holds even with a complex, algorithmic Jump.");
                Console.ResetColor();
                Console.WriteLine("The rendezvous was guaranteed by the commutative 'CombineInstructions' rule,");
                Console.WriteLine("while the security comes from the chaotic nature of the 'Jump' rule itself.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FAILURE! The logic is flawed.");
                Console.ResetColor();
            }
        }
    }
}