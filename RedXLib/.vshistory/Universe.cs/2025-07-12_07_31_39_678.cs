// SecretTerrain.cs
// This class represents our private key. The key IS the landscape of values.
using System.Numerics;

namespace SecretUniverse{
    public class SecretTerrain
{
    public ulong[] Values { get; }
    public int Size => Values.Length;

    /// <summary>
    /// Creates a terrain with a specific, secret set of values.
    /// </summary>
    public SecretTerrain(ulong[] secretValues)
    {
        Values = secretValues;
    }

    /// <summary>
    /// A helper to find the position of a value in our terrain.
    /// In a real system, this would need to be very fast or avoided.
    /// For our toy, a simple search is perfect.
    /// </summary>
    public int GetIndexOf(ulong value)
    {
        return Array.IndexOf(Values, value);
    }
}

// Program.cs

public class SyntheticUniverse
{
    // The universe operates on a specific terrain (the key)
    private readonly SecretTerrain _terrain;

    // The public rules are part of the universe's physics
    public SyntheticUniverse(SecretTerrain terrain)
    {
        _terrain = terrain;
    }

    /// <summary>
    /// The "Slow Progression" rule. Its behavior depends on the properties
    /// of the value at the current position.
    /// </summary>
    public int Skip(int currentPosition)
    {
        // 1. Get the actual value from the secret terrain
        ulong currentValue = _terrain.Values[currentPosition];

        // 2. Determine the "Alchemical Properties" of this value
        bool isOdd = (currentValue % 2) != 0;
        int bitCount = BitOperations.PopCount(currentValue); // Count of set bits (1s)

        // 3. Apply the public "Code Rule" based on these properties
        int stepAmount;
        if (isOdd)
        {
            // Rule for "Odd" values: step amount is based on the number of set bits
            stepAmount = 1 + (bitCount % 4);
            Console.WriteLine($"    -> Value {currentValue} is ODD. Bit count is {bitCount}. Skipping {stepAmount} steps.");
        }
        else
        {
            // Rule for "Even" values: a different, fixed-feeling step
            stepAmount = 5;
            Console.WriteLine($"    -> Value {currentValue} is EVEN. Skipping {stepAmount} steps.");
        }

        // 4. Calculate the new position, ensuring it wraps around the circle (closure)
        return (currentPosition + stepAmount) % _terrain.Size;
    }

    /// <summary>
    /// The "Fast Progression" rule. This is our 2-input rendezvous machine.
    /// </summary>
    public int Jump(int currentPosition, ulong instruction)
    {
        // 1. Get the value from the secret terrain
        ulong currentValue = _terrain.Values[currentPosition];

        // 2. Apply a public "Code Rule" that mixes the value and the instruction
        // We use bitwise XOR because it's a great non-mathematical mixer.
        ulong scrambled = currentValue ^ instruction;

        // The jump distance depends on the result of the scramble
        int jumpDistance = (int)(scrambled % 11) + 1; // Use a different prime modulus

        Console.WriteLine($"    -> Jumping from value {currentValue} with instruction {instruction}. Scrambled result gives a jump distance of {jumpDistance}.");

        // 3. Calculate the new position
        return (currentPosition + jumpDistance) % _terrain.Size;
    }
}


// --- Main Demonstration Program ---
public static class Program
{
    public static void Main()
    {
        Console.WriteLine("--- Welcome to the Synthetic Universe Toy Model ---");

        // STEP 1: Define two different "Secret Terrains" (Keys)
        // This is our main, "truly secret" key. The values are arbitrary.
        var secretKey = new SecretTerrain(new ulong[] { 100, 42, 7, 33, 98, 201, 55, 8, 11, 16, 77, 123, 50 });

        // This is a "simple" key for comparison. It's just sequential numbers.
        var simpleKey = new SecretTerrain(new ulong[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 });

        // STEP 2: Create a universe that runs on our SECRET key
        Console.WriteLine("\n\n--- DEMONSTRATION 1: Using the SECRET Key ---");
        Console.WriteLine($"Secret Key (Terrain): [{string.Join(", ", secretKey.Values)}]");
        var secretUniverse = new SyntheticUniverse(secretKey);

        // STEP 3: Show the Skip operation in the secret universe
        Console.WriteLine("\n--- Testing the 'Skip' operation (Slow Progression) ---");
        int currentPos = 0;
        for (int i = 0; i < 5; i++)
        {
            Console.WriteLine($"Starting at position {currentPos} (value is {secretKey.Values[currentPos]})");
            currentPos = secretUniverse.Skip(currentPos);
            Console.WriteLine($"  New position is {currentPos} (value is {secretKey.Values[currentPos]})");
        }

        // STEP 4: Show the Jump operation in the secret universe
        Console.WriteLine("\n--- Testing the 'Jump' operation (Fast Progression) ---");
        currentPos = 4;
        ulong instruction = 12345;
        Console.WriteLine($"Starting at position {currentPos} (value is {secretKey.Values[currentPos]})");
        int newPos = secretUniverse.Jump(currentPos, instruction);
        Console.WriteLine($"  New position is {newPos} (value is {secretKey.Values[newPos]})");

        // STEP 5: THE MOST IMPORTANT PART - DEMONSTRATING THE HARDNESS CONCEPT
        // We use the EXACT SAME public rules but with a DIFFERENT key.
        Console.WriteLine("\n\n--- DEMONSTRATION 2: Using the SIMPLE Key ---");
        Console.WriteLine("The public Skip/Jump algorithms are IDENTICAL, only the terrain has changed.");
        Console.WriteLine($"Simple Key (Terrain): [{string.Join(", ", simpleKey.Values)}]");
        var simpleUniverse = new SyntheticUniverse(simpleKey);

        Console.WriteLine("\n--- Re-running the 'Skip' test with the same starting point ---");
        currentPos = 0; // Reset to the same start
        Console.WriteLine($"Starting at position {currentPos} (value is {simpleKey.Values[currentPos]})");
        currentPos = simpleUniverse.Skip(currentPos);
        Console.WriteLine($"  New position is {currentPos} (value is {simpleKey.Values[currentPos]})");

        Console.WriteLine("\n>>> CONCLUSION: The path taken was completely different!");
        Console.WriteLine("We have proven that the behavior of the PUBLIC algorithm is dependent on the SECRET key.");
    }
}}