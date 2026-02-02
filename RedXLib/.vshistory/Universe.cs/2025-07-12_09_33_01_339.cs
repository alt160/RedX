// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Linq;
    using System.Numerics;

    // --- The Building Blocks of our Universe ---

    // An "Instruction" is our private key component.
    public record struct Instruction(long Multiplier, long Shift);

    // The "Terrain" is now a secret object, generated from a seed.
    // It acts as a shared secret key that defines the universe.
    public class Terrain
    {
        public int Size { get; }
        private readonly long[] _values;

        public Terrain(int size, int seed)
        {
            Size = size;
            _values = new long[size];

            var random = new Random(seed);
            for (int i = 0; i < size; i++)
            {
                // Generate pseudo-random 32-bit values for our terrain.
                _values[i] = random.Next();
            }
        }

        // The physics can now depend on the values of the terrain itself.
        public long GetValueAt(int position) => _values[position];

        public void PrintInfo()
        {
            Console.WriteLine($"  - Terrain generated with {Size} values. First 5: [{string.Join(", ", _values.Take(5))}...]");
        }
    }


    public class AlchemicalUniverse
    {
        private readonly Terrain _terrain; // The universe is now tied to a specific terrain.

        public AlchemicalUniverse(Terrain terrain)
        {
            _terrain = terrain;
        }

        // --- The Core Logic (First Principle Driven) ---

        // The "1-Inch Block": A public, commutative rule for combining instructions.
        public Instruction CombineInstructions(Instruction a, Instruction b)
        {
            // For simplicity, we use simple addition. This could be any commutative operation.
            long newMultiplier = a.Multiplier + b.Multiplier;
            long newShift = a.Shift + b.Shift;
            return new Instruction(newMultiplier, newShift);
        }

        // The "Mile Machine": Now fully algorithmic AND value-dependent.
        public int Jump(int startPosition, Instruction instruction)
        {
            // 1. Get the value from the SECRET terrain. This makes the physics key-dependent.
            long terrainValue = _terrain.GetValueAt(startPosition);

            // 2. The alchemical formula now incorporates the terrain's value.
            BigInteger bigPos = startPosition;
            BigInteger bigInstructionVal = instruction.Multiplier * instruction.Shift;
            BigInteger bigTerrainVal = terrainValue;
            BigInteger bigSize = _terrain.Size;

            // A chaotic, non-linear rule that mixes position, instruction, and the secret terrain.
            BigInteger newPosition = (bigPos * bigTerrainVal + bigInstructionVal) % bigSize;

            return (int)Math.Abs((long)newPosition);
        }

        public int GetGenesisPoint() => 0;
    }


    // --- Main Program to Demonstrate the Full System ---
    public static class Program
    {
        public static void Main()
        {
            Console.WriteLine("--- The Complete 'Secret Terrain' Key Exchange ---");

            // STEP 1: Alice and Bob secretly agree on a seed for their universe.
            // This seed generates their shared secret terrain.
            int sharedSeed = 1337;
            Console.WriteLine($"[1] Pre-shared secret seed: {sharedSeed}");

            var terrain = new Terrain(size: 257, seed: sharedSeed);
            var universe = new AlchemicalUniverse(terrain);

            Console.WriteLine("    A shared secret terrain has been generated from the seed.");
            terrain.PrintInfo();

            // STEP 2: Alice and Bob choose their private keys (secret instructions).
            var secret_a = new Instruction(Multiplier: 23, Shift: 78);
            var secret_b = new Instruction(Multiplier: 91, Shift: 12);
            Console.WriteLine($"\n[2] Alice's private key: {secret_a}");
            Console.WriteLine($"    Bob's private key:   {secret_b}");

            int genesisPoint = universe.GetGenesisPoint();

            // STEP 3: They calculate their PUBLIC keys by jumping from Genesis.
            Console.WriteLine("\n[3] Calculating Public Keys (The 'Context')...");
            int public_A = universe.Jump(genesisPoint, secret_a);
            int public_B = universe.Jump(genesisPoint, secret_b);
            Console.WriteLine($"    Alice's Public Key (a position on the terrain): {public_A}");
            Console.WriteLine($"    Bob's Public Key (a position on the terrain):   {public_B}");

            // STEP 4: The Rendezvous - "The Exchange of Context."
            Console.WriteLine("\n[4] Performing the Rendezvous...");

            // Alice uses Bob's PUBLIC key (B) and her PRIVATE key (a).
            // First, she must calculate the "master instruction" for the full journey.
            // This full journey is (b steps) then (a steps).
            var combined_for_Alice = universe.CombineInstructions(secret_b, secret_a);
            int final_A = universe.Jump(genesisPoint, combined_for_Alice);
            Console.WriteLine($"    Alice calculates the final shared secret position: {final_A}");

            // Bob uses Alice's PUBLIC key (A) and his PRIVATE key (b).
            // His full journey is (a steps) then (b steps).
            var combined_for_Bob = universe.CombineInstructions(secret_a, secret_b);
            int final_B = universe.Jump(genesisPoint, combined_for_Bob);
            Console.WriteLine($"    Bob calculates the final shared secret position:   {final_B}");

            // STEP 5: Verification.
            Console.WriteLine("\n[5] Verifying the Outcome...");
            if (final_A == final_B)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("    SUCCESS! A shared secret was created in a custom, secret universe.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("    FAILURE! The logic is flawed.");
            }
            Console.ResetColor();
        }
    }
}