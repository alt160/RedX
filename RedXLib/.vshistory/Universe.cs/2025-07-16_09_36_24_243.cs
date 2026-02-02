// This class represents our synthetic universe. It contains the public "Laws of Physics."
namespace TestCode
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Stub for PSI-RDV: produces a shared terrain R via private-set intersection.
    /// </summary>
    public static class PsiRdv
    {
        /// <summary>
        /// Runs a dummy PSI-RDV and returns an agreed terrain R (32-bit tokens).
        /// </summary>
        /// <remarks>
        /// <example>
        /// <code>
        /// var terrain = PsiRdv.Run(18, 5000);
        /// // 18-bit S count, minimum R size 5000
        /// </code>
        /// </example>
        /// </remarks>
        public static IList<int> Run(int sExponent, int minR)
        {
            // In real use, expand two private sets of size 2^sExponent,
            // then do exact PSI to form R with |R|>=minR.
            // Here: simulate by generating a random permutation of a large space
            int sSize = 1 << sExponent;
            var rnd = new Random(0xC0FFEE);
            var universe = Enumerable.Range(0, sSize).ToList();
            // Fisher-Yates shuffle
            for (int i = universe.Count - 1; i > 0; i--)
            {
                int j = rnd.Next(i + 1);
                (universe[i], universe[j]) = (universe[j], universe[i]);
            }
            // Take first minR elements as R
            return universe.Take(minR).ToList();
        }
    }

    /// <summary>
    /// Synthetic field over rendezvous terrain, supports only add and multiply.
    /// </summary>
    public class SyntheticField
    {
        private readonly IList<int> _terrain;
        private readonly HMACSHA256 _hmacAdd;
        private readonly HMACSHA256 _hmacMul;

        public SyntheticField(IList<int> terrain, byte[] keyAdd, byte[] keyMul)
        {
            _terrain = terrain;
            _hmacAdd = new HMACSHA256(keyAdd);
            _hmacMul = new HMACSHA256(keyMul);
        }

        public int Add(int x, int y) => PrfOp(_hmacAdd, x, y);
        public int Multiply(int x, int y) => PrfOp(_hmacMul, x, y);

        private int PrfOp(HMAC hmac, int a, int b)
        {
            int i = _terrain.IndexOf(a);
            int j = _terrain.IndexOf(b);
            if (i < 0 || j < 0)
                throw new ArgumentException("Elements must be in terrain.");
            byte[] data = BitConverter.GetBytes(i).Concat(BitConverter.GetBytes(j)).ToArray();
            byte[] hash = hmac.ComputeHash(data);
            uint idx = BitConverter.ToUInt32(hash, 0) % (uint)_terrain.Count;
            return _terrain[(int)idx];
        }
    }

    /// <summary>
    /// Trapdoor signature scheme over a synthetic field and rendezvous terrain.
    /// </summary>
    public class SyntheticFieldSignature
    {
        private readonly IList<int> _terrain;
        private readonly SyntheticField _field;
        private readonly int[] _coefficients;
        private readonly int _degree;

        /// <summary>
        /// Initializes the signature scheme.
        /// </summary>
        /// <param name="terrain">Shared rendezvous terrain.</param>
        /// <param name="field">Synthetic field instance.</param>
        /// <param name="coefficients">Polynomial coefficients for trapdoor.</param>
        /// <remarks>
        /// <example>
        /// <code>
        /// var terrain = PsiRdv.Run(18, 5000);
        /// var field = new SyntheticField(terrain, keyAdd, keyMul);
        /// int[] coeffs = { a0, a1, a2 }; // degree = 2
        /// var scheme = new SyntheticFieldSignature(terrain, field, coeffs);
        /// byte[] msg = Encoding.UTF8.GetBytes("Hello");
        /// var sig = scheme.Sign(msg);
        /// bool ok = scheme.Verify(msg, sig);
        /// </code>
        /// </example>
        /// </remarks>
        public SyntheticFieldSignature(IList<int> terrain, SyntheticField field, int[] coefficients)
        {
            _terrain = terrain;
            _field = field;
            _coefficients = coefficients;
            _degree = coefficients.Length - 1;
        }

        /// <summary>
        /// Signs a message by hashing into the terrain and inverting the trapdoor polynomial.
        /// </summary>
        public int Sign(byte[] message)
        {
            int target = HashToTerrainIndex(message);
            // Brute-force invert: find r in terrain s.t. Evaluate(r)==target
            foreach (int r in _terrain)
            {
                if (Evaluate(r) == target)
                    return r;
            }
            throw new InvalidOperationException("No valid signature found.");
        }

        /// <summary>
        /// Verifies a signature by forward-evaluating the polynomial.
        /// </summary>
        public bool Verify(byte[] message, int signature)
        {
            int idx = _terrain.IndexOf(signature);
            if (idx < 0) return false;
            int target = HashToTerrainIndex(message);
            return Evaluate(signature) == target;
        }

        private int Evaluate(int x)
        {
            // f(x) = a0 + a1*x + a2*x^2 + ... in synthetic field
            int result = _coefficients[0] >= 0 && _coefficients[0] < _terrain.Count
                ? _coefficients[0] : 0;
            for (int i = 1; i <= _degree; i++)
            {
                int term = x;
                for (int j = 1; j < i; j++)
                    term = _field.Multiply(term, x);
                int mul = _field.Multiply(_terrain[_coefficients[i]], term);
                result = _field.Add(result, mul);
            }
            return result;
        }

        private int HashToTerrainIndex(ReadOnlySpan<byte> msg)
        {
            // Use Blake3-256, take 32 bits, mod terrain size

            var h = Blake3.Hasher.Hash(msg);
            uint v = BitConverter.ToUInt32(h.AsSpan().ToArray(), 0);
            return (int)(v % _terrain.Count);
        }
    }

    public class Program
    {
        public static void Main()
        {
            // 1) Build the rendezvous terrain R (stubbed PSI-RDV)
            var terrain = PsiRdv.Run(sExponent: 18, minR: 5000);

            // 2) Instantiate the synthetic field with fresh PRF keys
            var keyAdd = Encoding.UTF8.GetBytes("add-key-bytes...");
            var keyMul = Encoding.UTF8.GetBytes("mul-key-bytes...");
            var field = new SyntheticField(terrain, keyAdd, keyMul);

            // 3) Choose trapdoor polynomial coefficients (degree d)
            //    Here: f(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2
            int[] coeffs = { 123, 45, 67 };
            var signer = new SyntheticFieldSignature(terrain, field, coeffs);

            // 4) Message to sign
            string message = "Hello, rendezvous!";
            byte[] msgBytes = Encoding.UTF8.GetBytes(message);

            // 5) Sign
            int signature = signer.Sign(msgBytes);
            Console.WriteLine($"Signature token: {signature}");

            // 6) Verify
            bool valid = signer.Verify(msgBytes, signature);
            Console.WriteLine($"Signature valid? {valid}");

            // 7) Tamper and verify fails
            bool bad = signer.Verify(msgBytes, signature ^ 1);
            Console.WriteLine($"Tampered valid? {bad}");
        }
    }

}
