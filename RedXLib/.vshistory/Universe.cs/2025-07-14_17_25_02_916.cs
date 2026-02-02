// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

        /// <summary>
        /// Represents the shared terrain R: an ordered list of 32-bit tokens.
        /// </summary>
        public class Terrain
        {
            public readonly List<int> R;
            private static readonly Random _rnd = new Random();

            /// <remarks>
            /// <code>
            /// // Create terrain of 12 random 32-bit tokens
            /// var terrain = Terrain.Create(12);
            /// </code>
            /// </remarks>
            public Terrain(List<int> tokens) => R = tokens;

            public static Terrain Create(int count)
            {
                var tokens = new HashSet<int>();
                while (tokens.Count < count)
                    tokens.Add(_rnd.Next());
                return new Terrain(tokens.ToList());
            }
        }

        /// <summary>
        /// Alice’s key: holds both forward & inverse maps (can encrypt & decrypt).
        /// </summary>
        public class AliceKey
        {
            private readonly int[] _forward;      // π: R[i] → m
            private readonly Dictionary<int, int> _inverse; // π⁻¹: m → R[i]
            private readonly List<int> _terrain;

            /// <param name="terrain">Shared terrain R</param>
            public AliceKey(Terrain terrain)
            {
                _terrain = terrain.R;
                int q = _terrain.Count;
                _forward = Enumerable.Range(0, q).ToArray();
                // Fisher–Yates shuffle to build random forward map
                var rnd = new Random();
                for (int i = q - 1; i > 0; i--)
                {
                    int j = rnd.Next(i + 1);
                    (_forward[i], _forward[j]) = (_forward[j], _forward[i]);
                }
                // Build inverse
                _inverse = new Dictionary<int, int>(q);
                for (int i = 0; i < q; i++)
                    _inverse[_forward[i]] = i;
            }

            /// <summary>
            /// Encrypts a plaintext m→token c.
            /// </summary>
            public int Encrypt(int m)
            {
                if (!_inverse.TryGetValue(m, out var idx))
                    throw new ArgumentOutOfRangeException(nameof(m));
                return _terrain[idx];
            }

            /// <summary>
            /// Decrypts a token c→plaintext m.
            /// </summary>
            public int Decrypt(int c)
            {
                int idx = _terrain.IndexOf(c);
                if (idx < 0) throw new ArgumentException("Invalid token", nameof(c));
                return _forward[idx];
            }

            /// <summary>
            /// Expose only the forward map and R to Bob.
            /// </summary>
            public (int[] forward, List<int> terrain) ExportPublic()
                => (_forward, _terrain.ToList());
        }

        /// <summary>
        /// Bob’s key: holds only forward & R (decrypt-only).
        /// </summary>
        public class BobKey
        {
            private readonly int[] _forward;
            private readonly List<int> _terrain;

            /// <param name="forward">Alice’s public forward map</param>
            /// <param name="terrain">Shared terrain R</param>
            public BobKey(int[] forward, List<int> terrain)
            {
                _forward = forward;
                _terrain = terrain;
            }

            /// <summary>
            /// Decrypts a token c→plaintext m.
            /// Throws if c not in R or forward map yields out-of-range.
            /// </summary>
            public int Decrypt(int c)
            {
                int idx = _terrain.IndexOf(c);
                if (idx < 0) throw new ArgumentException("Invalid token", nameof(c));
                int m = _forward[idx];
                if (m < 0 || m >= _forward.Length)
                    throw new InvalidOperationException("Garbled ciphertext");
                return m;
            }

            // No Encrypt method: Bob cannot generate valid tokens.
        }

        public class Program
        {
            public static void Main()
            {
                // 1) Setup terrain and keys
                var terrain = Terrain.Create(count: 12);
                var alice = new AliceKey(terrain);
                var (forward, R) = alice.ExportPublic();
                var bob = new BobKey(forward, R);

                // 2) Alice encrypts plaintext 5
                int plaintext = 5;
                int ciphertext = alice.Encrypt(plaintext);
                Console.WriteLine($"Ciphertext token: {ciphertext:X8}");

                // 3) Bob decrypts valid ciphertext
                int recovered = bob.Decrypt(ciphertext);
                Console.WriteLine($"Bob recovered m = {recovered}");

                // 4) Bob rejects contrived ciphertext
                try
                {
                    bob.Decrypt(unchecked((int)0xDEADBEEF));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Decryption failed: {ex.Message}");
                }

                // 5) Bob cannot encrypt (no method available).
            }
        }
    }
