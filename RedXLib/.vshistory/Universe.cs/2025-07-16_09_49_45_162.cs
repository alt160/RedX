// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// Simple Bloom Filter for PSI without revealing seeds.
    /// </summary>
    public class BloomFilter<T>
    {
        private readonly BitArray _bits;
        private readonly int _size;
        private readonly int _hashCount;
        private readonly Func<T, int, int> _hashFunc;

        public BloomFilter(int size, int hashCount, Func<T, int, int> hashFunc)
        {
            _size = size;
            _hashCount = hashCount;
            _bits = new BitArray(size);
            _hashFunc = hashFunc;
        }

        public void Add(T item)
        {
            for (int i = 0; i < _hashCount; i++)
            {
                int h = _hashFunc(item, i) & 0x7FFFFFFF;
                _bits[h % _size] = true;
            }
        }

        public bool Contains(T item)
        {
            for (int i = 0; i < _hashCount; i++)
            {
                int h = _hashFunc(item, i) & 0x7FFFFFFF;
                if (!_bits[h % _size]) return false;
            }
            return true;
        }
    }

    /// <summary>
    /// PSI-RDV simulation: Alice builds a Bloom filter, Bob probes it to compute R.
    /// </summary>
    public static class PsiRdv
    {
        /// <summary>
        /// Alice builds and sends a Bloom filter over her set S1.
        /// </summary>
        public static BloomFilter<int> BuildFilter(byte[] seedA, int sSize, int bfSize, int hashCount)
        {
            var s1 = ExpandSet(seedA, sSize);
            var bf = new BloomFilter<int>(bfSize, hashCount, HashFunction);
            foreach (var x in s1) bf.Add(x);
            return bf;
        }

        /// <summary>
        /// Bob receives Alice's filter, expands his set S2, and computes R = S1 ∩ S2.
        /// </summary>
        public static List<int> ComputeIntersection(byte[] seedB, int sSize,
                                                   BloomFilter<int> receivedFilter)
        {
            var s2 = ExpandSet(seedB, sSize);
            var intersection = new List<int>();
            foreach (var y in s2)
            {
                if (receivedFilter.Contains(y) && s2.Contains(y))
                    intersection.Add(y);
            }
            return intersection;
        }

        // PRF-based expansion to a unique set
        private static HashSet<int> ExpandSet(byte[] seed, int count)
        {
            var set = new HashSet<int>();
            using var hmac = new HMACSHA256(seed);
            uint counter = 0;
            while (set.Count < count)
            {
                byte[] block = BitConverter.GetBytes(counter++);
                byte[] hash = hmac.ComputeHash(block);
                int val = BitConverter.ToInt32(hash, 0);
                set.Add(val);
            }
            return set;
        }

        // Simple seeded mix function
        private static int HashFunction(int value, int seed)
        {
            unchecked
            {
                const int FNV_offset = unchecked((int)2166136261);
                const int FNV_prime = 16777619;
                int h = FNV_offset;
                h ^= value;
                h *= FNV_prime;
                h ^= seed;
                h *= FNV_prime;
                return h;
            }
        }
    }

    // Usage example (in Program.cs):
    // // Alice's side:
    // var bf = PsiRdv.BuildFilter(seedA, 1<<18, 1<<20, 4);
    // // Bob's side:
    // var R = PsiRdv.ComputeIntersection(seedB, 1<<18, bf);


}
