using Blake3;
using System.Data;
using System.Numerics;
using static System.Runtime.InteropServices.JavaScript.JSType;

 using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace NewUniverse{// This class holds the public "Laws of Physics" for our universe.
// Anyone can see and use these rules.
public static class Universe
{
    // ENCRYPTION RULE: A public, one-way "alchemical" process.
    // It takes a message (which is a position on the terrain) and the public terrain.
    // It seems one-way because reversing it requires knowing the secret trapdoor.
    public static long Encrypt(Terrain publicKey, int messagePosition)
    {
        if (messagePosition < 0 || messagePosition >= publicKey.Size)
            throw new ArgumentOutOfRangeException(nameof(messagePosition), "Message is not a valid position on the Terrain.");

        // 1. Find the value at the message's position on the public terrain.
        long value_at_position = publicKey.GetValueAt(messagePosition);

        // 2. Apply a public, deterministic "scrambling" function.
        // We'll use a simple modular exponentiation. It's a classic one-way function.
        // The public exponent 'e' is well-known (often 65537 in real RSA).
        BigInteger publicExponent = 65537;

        // The result is the ciphertext. An outsider can't easily reverse this
        // without knowing the secrets of the terrain's modulus.
        long ciphertext = (long)BigInteger.ModPow(value_at_position, publicExponent, publicKey.Modulus);

        return ciphertext;
    }

    // DECRYPTION RULE: This is the "trapdoor" function.
    // It requires the private key to reverse the encryption.
    public static int Decrypt(Terrain publicKey, PrivateKey privateKey, long ciphertext)
    {
        // 1. Use the SECRET "decryption exponent" from the private key to reverse the scrambling.
        // This is the trapdoor in action.
        BigInteger original_value_big = BigInteger.ModPow(ciphertext, privateKey.DecryptionExponent, publicKey.Modulus);
        long original_value = (long)original_value_big;

        // 2. Now that we have the original value, we need to find its position on the terrain.
        // An outsider would have to search the entire terrain. But we can use the private key's
        // "generator function" to find it instantly.
        int original_position = privateKey.FindPosition(original_value);

        return original_position;
    }
}

// Represents the Public Key: a specific "Terrain" of values.
public class Terrain
{
    private readonly IReadOnlyList<long> _values;
    private readonly Dictionary<long, int> _valueToPositionMap;

    public int Size => _values.Count;
    public long Modulus { get; }

    public Terrain(List<long> values, long modulus)
    {
        _values = values;
        Modulus = modulus;

        // Create a fast lookup map for finding positions
        _valueToPositionMap = new Dictionary<long, int>();
        for (int i = 0; i < values.Count; i++)
        {
            _valueToPositionMap[values[i]] = i;
        }
    }

    public long GetValueAt(int position) => _values[position];
    public int GetPositionOf(long value) => _valueToPositionMap[value];

    public void Print(int take = 16)
    {
        Console.WriteLine($"  Terrain of {Size} values (Modulus: {Modulus}). Showing first {take}:");
        Console.WriteLine($"  [{string.Join(", ", _values.Take(take))} ...]");
    }
}

// Represents the Private Key: the secret knowledge behind the Terrain.
public class PrivateKey
{
    // The secret parameters of the generator function f(x) = (Multiplier * x + Increment) % Modulus
    private long Multiplier { get; }
    private long Increment { get; }
    private long Modulus { get; }

    // The TRAPDOOR: The modular inverse of the multiplier, which allows us to run the generator backwards.
    private long MultiplierInverse { get; }

    // The TRAPDOOR for the public scrambling function.
    public BigInteger DecryptionExponent { get; }

    public PrivateKey(long m, long i, long mod, BigInteger d)
    {
        Multiplier = m;
        Increment = i;
        Modulus = mod;
        DecryptionExponent = d;
        MultiplierInverse = (long)ModInverse(m, mod); // Pre-calculate the trapdoor
    }

    // This is the secret, fast way to find a value's original position (its index).
    public int FindPosition(long value)
    {
        // Run the generator function f(x) in reverse using the trapdoor.
        // f_inv(y) = (y - c) * a_inv % m
        BigInteger temp = value - Increment;
        temp = (temp * MultiplierInverse) % Modulus;
        if (temp < 0) temp += Modulus; // Ensure result is positive
        return (int)temp;
    }

    // Helper function to find the modular multiplicative inverse
    private static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        return BigInteger.ModPow(a, m - 2, m); // Using Fermat's Little Theorem for prime m
    }
}

// Responsible for creating a key pair with a hidden structure.
public class KeyGenerator
{
    private readonly int _terrainSize;

    // We need large prime numbers for this to work.
    // For our toy, we'll pick two small primes and create a modulus.
    private readonly long _p = 499; // A prime number
    private readonly long _q = 547; // Another prime number

    public KeyGenerator(int terrainSize)
    {
        _terrainSize = terrainSize;
    }

    public (Terrain PublicKey, PrivateKey PrivateKey) GenerateKeyPair()
    {
        // --- 1. Create the secret mathematical foundation ---
        long modulus = _p * _q;
        BigInteger phi = (_p - 1) * (_q - 1); // Euler's totient function

        // --- 2. Create the secret "generator" function f(x) ---
        // f(x) = (multiplier * x + increment) % modulus
        // The multiplier must be coprime to the terrain size for a full cycle.
        long multiplier = 31;
        long increment = 73;

        // --- 3. Generate the Terrain (the Public Key) ---
        var values = new List<long>(_terrainSize);
        for (int i = 0; i < _terrainSize; i++)
        {
            long val = (multiplier * (long)i + increment) % modulus;
            values.Add(val);
        }
        var publicKey = new Terrain(values, modulus);

        // --- 4. Create the Private Key containing the trapdoor ---
        BigInteger publicExponent = 65537;
        BigInteger decryptionExponent = BigInteger.ModPow(publicExponent, phi - 1, phi); // Modular inverse

        var privateKey = new PrivateKey(multiplier, increment, modulus, decryptionExponent);

        return (publicKey, privateKey);
    }
}


// --- Main Program to Demonstrate the System ---
public class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("--- Building a Toy 'Secret Terrain' Cryptosystem ---");

        // We need a terrain big enough to be interesting.
        const int TERRAIN_SIZE = 128;

        // 1. Generate a new key pair. This creates a new universe.
        Console.WriteLine("\n[1] Generating a new Public/Private Key Pair...");
        var keygen = new KeyGenerator(TERRAIN_SIZE);
        var (publicKey, privateKey) = keygen.GenerateKeyPair();
        publicKey.Print();

        // 2. Define a secret message. The message is a *position* on the terrain.
        int originalMessage = 42;
        Console.WriteLine($"\n[2] Original secret message is the position: {originalMessage}");
        Console.WriteLine($"    (The value at this position is: {publicKey.GetValueAt(originalMessage)})");

        // 3. Encrypt the message using only the Public Key and Public Rules.
        Console.WriteLine("\n[3] Encrypting the message using ONLY the Public Key...");
        long ciphertext = Universe.Encrypt(publicKey, originalMessage);
        Console.WriteLine($"    Ciphertext produced: {ciphertext}");

        // 4. Decrypt the message using the Private Key (the trapdoor).
        Console.WriteLine("\n[4] Decrypting the ciphertext using the Private Key...");
        int decryptedMessage = Universe.Decrypt(publicKey, privateKey, ciphertext);
        Console.WriteLine($"    Decrypted message is the position: {decryptedMessage}");

        // 5. Verify the result.
        Console.WriteLine("\n[5] Verifying the result...");
        if (originalMessage == decryptedMessage)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("    SUCCESS! The original message was recovered.");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("    FAILURE! The decrypted message does not match the original.");
        }
        Console.ResetColor();
    }
}
}