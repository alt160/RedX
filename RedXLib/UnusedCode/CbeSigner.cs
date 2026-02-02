using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CodeBasedSignature
{
    /// <summary>
    /// Implements a simple code-based signature encoder and verifier using a single key buffer.
    /// </summary>
    public class CbeSigner
    {
        private readonly ReadOnlyMemory<byte> _key;
        private readonly int _blockCount;
        private readonly int _noiseLength;
        private const int PermBlockSize = 256;

        /// <summary>
        /// Initializes a new instance with a contiguous key buffer and noise length per byte.
        /// </summary>
        /// <param name="key">Secret key: N * 256-byte shuffled permutation blocks.</param>
        /// <param name="noiseLength">Number of noise bytes per message byte (>=1).</param>
        public CbeSigner(ReadOnlySpan<byte> key, int noiseLength = 8)
        {
            if (key.Length % PermBlockSize != 0 || key.Length == 0)
                throw new ArgumentException("Key must be non-empty and a multiple of 256 bytes", nameof(key));
            if (noiseLength < 1)
                throw new ArgumentOutOfRangeException(nameof(noiseLength), "Noise length must be at least 1.");

            _key = key.ToArray();
            _blockCount = _key.Length / PermBlockSize;
            _noiseLength = noiseLength;
        }

        /// <summary>
        /// Signs the given message, producing a raw signature of length message.Length * noiseLength.
        /// </summary>
        public byte[] Sign(ReadOnlySpan<byte> message)
        {
            var fullHash = SHA256.Create().ComputeHash(message.ToArray());
            int msgLen = message.Length;
            var signature = new byte[msgLen * _noiseLength];

            for (int i = 0; i < msgLen; i++)
            {
                byte plain = message[i];
                var keySpan = _key.Slice((i % _blockCount) * PermBlockSize, PermBlockSize).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    throw new InvalidOperationException("Plain byte not found in key block");

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_noiseLength == 1 ? 1 : _noiseLength - 1)) + 1;

                var dest = signature.AsSpan(i * _noiseLength, _noiseLength);
                for (int j = 0; j < _noiseLength; j++)
                    dest[j] = keySpan[(dIndex + j * step) & 0xFF];
            }

            return signature;
        }

        /// <summary>
        /// Verifies that the signature matches the message using the secret key.
        /// </summary>
        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != message.Length * _noiseLength)
                return false;

            var fullHash = SHA256.Create().ComputeHash(message.ToArray());
            int msgLen = message.Length;

            for (int i = 0; i < msgLen; i++)
            {
                byte plain = message[i];
                var keySpan = _key.Slice((i % _blockCount) * PermBlockSize, PermBlockSize).Span;
                int cIndex = keySpan.IndexOf(plain);
                if (cIndex < 0)
                    return false;

                byte param = (byte)(fullHash[i % fullHash.Length] ^ keySpan[cIndex]);
                int dIndex = (cIndex + param) & 0xFF;
                int step = (param % (_noiseLength == 1 ? 1 : _noiseLength - 1)) + 1;

                var seg = signature.Slice(i * _noiseLength, _noiseLength);
                for (int j = 0; j < _noiseLength; j++)
                    if (seg[j] != keySpan[(dIndex + j * step) & 0xFF])
                        return false;
            }

            return true;
        }

        /// <summary>
        /// Verifies that a signature matches a message using the given public key buffer.
        /// </summary>
        /// <param name="message">Original plaintext bytes.</param>
        /// <param name="signature">Signature bytes to verify.</param>
        /// <param name="publicKey">Public key buffer: N * 256-byte permutation blocks.</param>
        /// <param name="noiseLength">Noise length used during signing.</param>
        public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey, int noiseLength)
        {
            var verifier = new CbeSigner(publicKey, noiseLength);
            return verifier.Verify(message, signature);
        }

        /// <summary>
        /// Generates a single key buffer of N * 256 bytes via Fisher-Yates.
        /// </summary>
        public static byte[] GenerateRandomKey(int blocks)
        {
            if (blocks < 1)
                throw new ArgumentOutOfRangeException(nameof(blocks), "Must generate at least one block");
            var key = new byte[blocks * PermBlockSize];
            for (int b = 0; b < blocks; b++)
            {
                for (int i = 0; i < PermBlockSize; i++) key[b * PermBlockSize + i] = (byte)i;
                for (int i = PermBlockSize - 1; i > 0; i--)
                {
                    int j = RandomNumberGenerator.GetInt32(i + 1);
                    int idx = b * PermBlockSize;
                    (key[idx + i], key[idx + j]) = (key[idx + j], key[idx + i]);
                }
            }
            return key;
        }
    }
}
 
public class XorHashAsymmetricCipher
{
    private readonly byte[] mPriv = new byte[256];
    private readonly ulong[] mPub = new ulong[256]; // 64-bit hashes

    public XorHashAsymmetricCipher()
    {
        InitializeKeys();
    }

    /// <summary>
    /// Generates mPriv as a Yates-shuffled permutation of 0..255 and derives mPub from SHA-512 truncated to 64 bits
    /// </summary>
    private void InitializeKeys()
    {
        var seed = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        Shuffle(seed);
        Buffer.BlockCopy(seed, 0, mPriv, 0, 256);

        using var sha = SHA512.Create();
        for (int i = 0; i < 256; i++)
        {
            var input = new byte[] { mPriv[i], (byte)i };
            var hash = sha.ComputeHash(input);
            mPub[i] = BitConverter.ToUInt64(hash, 0); // Use first 8 bytes
        }
    }

    private void Shuffle(byte[] array)
    {
        var rng = RandomNumberGenerator.Create();
        for (int i = array.Length - 1; i > 0; i--)
        {
            var box = new byte[1];
            do rng.GetBytes(box); while (box[0] >= i * (byte.MaxValue / i));
            int j = box[0] % (i + 1);
            (array[i], array[j]) = (array[j], array[i]);
        }
    }

    /// <summary>
    /// Encrypts a byte using mPub. Returns a 4-byte block.
    /// </summary>
    public byte[] EncryptByte(byte plainByte)
    {
         var index = RandomNumberGenerator.GetInt32(0, 256);
        var hash = BitConverter.GetBytes(mPub[index]);
        var byteIndex = RandomNumberGenerator.GetInt32(0, 4);

        var cipherByte = (byte)(plainByte ^ hash[byteIndex]);
        var result = new byte[4];
        result[0] = cipherByte;
        int ri = 1;
        for (int i = 0; i < 4; i++)
        {
            if (i == byteIndex) continue;
            result[ri++] = hash[i];
        }
        return result;
    }

    /// <summary>
    /// Decrypts a 4-byte block into the original byte using mPriv.
    /// </summary>
    public byte? DecryptByte(byte[] block)
    {
        if (block.Length != 4) return null;
        var cipherByte = block[0];

        using var sha = SHA512.Create();
        for (int i = 0; i < 256; i++)
        {
            var input = new byte[] { mPriv[i], (byte)i };
            var hash = sha.ComputeHash(input);
            var h64 = BitConverter.ToUInt64(hash, 0);
            var bytes = BitConverter.GetBytes(h64);

            for (int b = 0; b < 4; b++)
            {
                var plain = (byte)(cipherByte ^ bytes[b]);
                var probe = new byte[4];
                probe[0] = cipherByte;
                int ri = 1;
                for (int j = 0; j < 4; j++)
                {
                    if (j == b) continue;
                    probe[ri++] = bytes[j];
                }
                if (probe[1] == block[1] && probe[2] == block[2] && probe[3] == block[3])
                    return plain;
            }
        }
        return null; // Decryption failed
    }

    /// <summary>
    /// Encrypts a string into ciphertext blocks
    /// </summary>
    public List<byte[]> Encrypt(string message)
    {
        var data = Encoding.UTF8.GetBytes(message);
        var result = new List<byte[]>();
        foreach (var b in data)
            result.Add(EncryptByte(b));
        return result;
    }

    /// <summary>
    /// Decrypts a list of ciphertext blocks into the original string
    /// </summary>
    public string? Decrypt(List<byte[]> blocks)
    {
        var bytes = new List<byte>();
        foreach (var block in blocks)
        {
            var b = DecryptByte(block);
            if (b == null) return null;
            bytes.Add(b.Value);
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }
}