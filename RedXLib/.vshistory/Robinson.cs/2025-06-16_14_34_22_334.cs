using System.Diagnostics;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RobinsonEncryptionLib
{
    public static class RE
    {

        public static REKey CreateKey(byte keySize = 8)
        {
            return new REKey(keySize);
        }

        public static BufferStream Encrypt(byte[] data, REKey keyA, REKey keyB)
        {
            // buffer to hold cipher text
            var outBuf = new BufferStream();

            // do first round transform of data thru keyA
            var dataMappedByKeyA = keyA.MapData(data);

            // encrypted data with keyB
            var dataMappedByKeyB = keyB.MapData(dataMappedByKeyA.skips.AsReadOnlySpan);

            // put dataMappedByKeyA kStar into a buffer
            //Debug.WriteLine(dataMappedByKeyA.kStar.Count, "kStar Count");
            var kStarBuffer = new BufferStream();
            foreach (var kv in dataMappedByKeyA.kStar)
            {
                kStarBuffer.Write(kv.Key);
                kStarBuffer.Write(kv.Value);
                //Debug.WriteLine($"{kv.Key}, {kv.Value}", "kStar values");
            }
            // encrypt kStar with keyB
            kStarBuffer.Position = 0;
            //var aStarMappedByKeyB = keyB.CreateDataMap(kStarBuffer.AsReadOnlySpan);

            // create random length prefix of random bytes
            var prefix = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(17, 64));

            // write prefix length, prefix, aStar, and mapped data to outBuf
            // Encrypted payload structure:
            // [prefixLength:1][prefix:N][aStarLength:7bit][aStarMapped][dataMappedByKeyA]
            outBuf.Write((byte)prefix.Length);
            //Debug.WriteLine(prefix.Length, "prefix length");
            outBuf.WriteBytes(prefix);
            //Debug.WriteLine(BitConverter.ToString(prefix));
            outBuf.Write7BitUInt((uint)dataMappedByKeyA.kStar.Count);
            kStarBuffer.CopyTo(outBuf);
            //Debug.WriteLine(BitConverter.ToString(kStarBuffer.ReadOnlySpan(0, Math.Min(16, (int)kStarBuffer.Length)).ToArray()), $"kStarBuffer first {Math.Min(16, (int)kStarBuffer.Length)} bytes");
            dataMappedByKeyA.skips.CopyTo(outBuf);

            // encrypt outBuf with keyB
            var outBufMappedByKeyB = keyB.MapData(outBuf.AsReadOnlySpan);
            //Debug.WriteLine(outBufMappedByKeyB.skips.Length, "outBufMappedByKeyB length");
            //Debug.WriteLine(BitConverter.ToString(outBufMappedByKeyB.skips.ReadOnlySpan(0, 16).ToArray()), "outBufMappedByKeyB first 16 bytes");
            // calc sha256 of outBuf
            outBufMappedByKeyB.skips.Position = 0;
            var prefixSha256 = SHA256.HashData(outBufMappedByKeyB.skips.AsReadOnlySpan);
            //Debug.WriteLine(BitConverter.ToString(prefixSha256), "hash");

            // encrypt hash with keyB
            var encryptedHash = keyB.MapData(prefixSha256.AsSpan());
            //Debug.WriteLine(encryptedHash.skips.Length, "encrypted hash length");

            // final buffer
            var finalBuf = new BufferStream();
            finalBuf.Write7BitUInt((uint)encryptedHash.skips.Length);
            finalBuf.Write(encryptedHash.skips);
            finalBuf.Write(outBufMappedByKeyB.skips);

            return finalBuf;
        }

        public static BufferStream Decrypt(byte[] ciphertext, REKey keyB)
        {
            // overlay BufferStream over ciphertext
            var cipherStream = new BufferStream(ciphertext);

            // read encrypted hash length
            var hashLength = (int)cipherStream.Read7BitUInt();

            // read encrypted hash as slice
            var hash = keyB.UnmapData(cipherStream.ReadBytes(hashLength));

            BufferStream encryptedData = cipherStream.SegmentAtCurrent();
            var computedHash = SHA256.HashData(encryptedData.AsReadOnlySpan);

            // check hash
            if (!hash.AsReadOnlySpan.SequenceEqual(computedHash))
                return null;

            // decrypt thru keyB
            var decryptedPayload = keyB.UnmapData(cipherStream.SegmentAtCurrent());

            var decryptedStream = new BufferStream(decryptedPayload);
            // read prefix length
            var prefixLength = decryptedStream.Read7BitUInt();

            // skip prefix
            decryptedStream.Position += prefixLength;

            // read aStar length
            var aStarCount = (int)decryptedStream.Read7BitUInt();
            var aStarSegment = decryptedStream.SliceAtCurrent(aStarCount);
            var aStar = new Dictionary<short, byte>();
            for (int i = 0; i < aStarCount; i++)
            {
                var index = decryptedStream.ReadInt16();
                var byteValue = decryptedStream.ReadByte();
                aStar[index] = byteValue;
            }

            // decrypt ciphertext with aStar
            var plainText = keyB.UnmapData(decryptedStream.SegmentAtCurrent(), aStar);

            return plainText;


        }

    }

    public class REKey
    {
        internal byte[] key;
        internal short[] rkd;
        byte _keySize;
        public REKey(byte keySize = 8)
        {
            if (keySize < 2)
                throw new ArgumentException("Key size must be at least 1", nameof(keySize));
            _keySize = keySize;
            using var keyData = new BufferStream();
            rkd = new short[256 * keySize];
            var idx = (short)0;
            for (int i = 0; i < keySize; i++)
            {
                var array = new byte[256];
                for (short a = 0; a < array.Length; a++)
                {
                    array[a] = (byte)a;
                }



                Shuffle(array.AsSpan());

                for (int j = 0; j < array.Length; j++)
                {
                    rkd[array[j] + i] = idx++;
                    keyData.Write(array[j]);
                }
            }
            key = keyData.ToArray();
        }

        public (BufferStream skips, Dictionary<short, byte> kStar) MapData(ReadOnlySpan<byte> data)
        {
            // Random start location within the key
            int sl = RandomNumberGenerator.GetInt32(0, key.Length);

            // Buffer to record skip distances (effectively the ciphertext)
            var skips = new BufferStream();

            // Dictionary mapping each final key position to its corresponding input byte
            var kStar = new Dictionary<short, byte>(data.Length);

            // Write the initial position to the output
            skips.Write((short)sl);

            // Initialize current position
            var curPos = (short)sl;

            // Define block layout assumptions (each block is 256 bytes)
            int blockSize = 256;
            int blockCount = _keySize;

            // Process each byte of input data
            for (int dataIndex = 0; dataIndex < data.Length; dataIndex++)
            {
                byte b = data[dataIndex];

                // Optionally apply counter shift to resist repetition patterns
                b = (byte)((b + dataIndex) % 256);

                // Get the list of key indexes for this byte value
                var rkdIndexes = rkd.AsSpan(b * _keySize, _keySize);

                short target = -1;
                int distance = int.MaxValue;

                for (int rkdIndex = 0; rkdIndex < rkdIndexes.Length; rkdIndex++)
                {
                    short rawIndex = rkdIndexes[rkdIndex];

                    int d = rawIndex - curPos;
                    if (d > 0)
                    {
                        target = rawIndex;
                        distance = d;
                        break;
                    }
                }

                // If no forward index found, wrap around
                if (target == -1)
                {
                    short rawIndex = rkdIndexes[0];
                    target = rawIndex;
                    distance = (target - curPos) + key.Length;
                }

                // Emit skip value
                if (distance >= 256)
                {
                    skips.WriteByte(0); // escape marker

                    if (distance == 512)
                        skips.WriteByte(0); // reserved
                    else
                        skips.WriteByte((byte)(distance - 255)); // shift to range 1–256
                }
                else
                {
                    skips.WriteByte((byte)distance);
                }

                // Advance cursor
                curPos = (short)((curPos + distance) % key.Length);

                // Record in kStar
                kStar[curPos] = b;
            }

            return (skips, kStar);
        }




        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static byte CalcRotation(int distance)
        {
            uint d = (uint)distance;
            d ^= d >> 3;
            d ^= d << 5;
            d ^= d >> 7;
            byte rot = (byte)((d * 0xA3) & 0xFF); // Multiplicative scrambling
            return rot == 0 ? (byte)1 : rot; // Avoid zero
        }


        public BufferStream UnmapData(BufferStream skips)
        {
            var result = new BufferStream();

            short curPos = skips.ReadInt16(); // initial position
            while (skips.Position < skips.Length)
            {
                int distance;

                var b = skips.ReadByte();
                if (b == 0)
                    distance = skips.Read7BitInt(); // extended skip
                else
                    distance = b; // inline short skip

                // apply circular offset
                curPos = (short)((curPos + distance) % key.Length);

                var value = key[curPos];
                result.WriteByte(value);
            }
            result.Position = 0;
            return result;
        }
        public BufferStream UnmapData(Memory<byte> skipsSpan)
        {
            var result = new BufferStream();
            var skips = new BufferStream(skipsSpan);

            short curPos = skips.ReadInt16(); // initial position
            while (skips.Position < skips.Length)
            {
                int distance;

                var b = skips.ReadByte();
                if (b == 0)
                    distance = skips.Read7BitInt(); // extended skip
                else
                    distance = b; // inline short skip

                // apply circular offset
                curPos = (short)((curPos + distance) % key.Length);

                var value = key[curPos];
                result.WriteByte(value);
            }
            result.Position = 0;
            return result;
        }
        public BufferStream UnmapData(BufferStream skips, Dictionary<short, byte> kStar)
        {
            // Output buffer for reconstructed plaintext
            var output = new BufferStream();

            // Initial cursor position
            short curPos = skips.ReadInt16();

            int dataIndex = 0;

            while (skips.Position < skips.Length)
            {
                int distance;

                byte b = skips.ReadByte();
                if (b == 0)
                {
                    byte delta = skips.ReadByte();
                    distance = (delta == 0) ? 512 : (delta + 255);
                }
                else
                {
                    distance = b;
                }

                // Advance cursor
                curPos = (short)((curPos + distance) % key.Length);

                // Recover original byte
                byte encoded = kStar[curPos];

                // Undo counter shift
                byte original = (byte)((256 + encoded - dataIndex) % 256);

                output.WriteByte(original);
                dataIndex++;
            }

            return output;
        }


        /// <summary>
        /// Performs a Fisher-Yates shuffle on a Memory<byte>
        /// </summary>
        /// <param name="memory">The memory to shuffle</param>
        /// <param name="random">Optional random number generator (uses cryptographically secure RNG if null)</param>
        public static void Shuffle(Memory<byte> memory, Random? random = null)
        {
            if (memory.IsEmpty || memory.Length <= 1)
                return;

            // Get a span for direct access
            Span<byte> span = memory.Span;

            // Use cryptographically secure random if none provided
            bool useSecureRandom = random == null;

            // Fisher-Yates shuffle algorithm
            for (int i = span.Length - 1; i > 0; i--)
            {
                // Generate a random index between 0 and i (inclusive)
                int j;
                if (useSecureRandom)
                    j = RandomNumberGenerator.GetInt32(i + 1);
                else
                    j = random!.Next(i + 1);

                // Swap elements at i and j
                byte temp = span[i];
                span[i] = span[j];
                span[j] = temp;
            }
        }

        /// <summary>
        /// Performs a Fisher-Yates shuffle on a Memory<byte>
        /// </summary>
        /// <param name="memory">The memory to shuffle</param>
        /// <param name="random">Optional random number generator (uses cryptographically secure RNG if null)</param>
        public static void Shuffle(Span<byte> span, Random? random = null)
        {
            if (span.IsEmpty || span.Length <= 1)
                return;


            // Use cryptographically secure random if none provided
            bool useSecureRandom = random == null;

            // Fisher-Yates shuffle algorithm
            for (int i = span.Length - 1; i > 0; i--)
            {
                // Generate a random index between 0 and i (inclusive)
                int j;
                if (useSecureRandom)
                    j = RandomNumberGenerator.GetInt32(i + 1);
                else
                    j = random!.Next(i + 1);

                // Swap elements at i and j
                byte temp = span[i];
                span[i] = span[j];
                span[j] = temp;
            }
        }


        /// <summary>
        /// Performs a Fisher-Yates shuffle on a byte array
        /// </summary>
        /// <param name="array">The array to shuffle</param>
        /// <param name="random">Optional random number generator (uses cryptographically secure RNG if null)</param>
        private static void Shuffle(byte[] array, Random? random = null)
        {
            if (array == null || array.Length <= 1)
                return;

            // Use cryptographically secure random if none provided
            bool useSecureRandom = random == null;

            // Fisher-Yates shuffle algorithm
            for (int i = array.Length - 1; i > 0; i--)
            {
                // Generate a random index between 0 and i (inclusive)
                int j;
                if (useSecureRandom)
                    j = RandomNumberGenerator.GetInt32(i + 1);
                else
                    j = random!.Next(i + 1);

                // Swap elements at i and j
                byte temp = array[i];
                array[i] = array[j];
                array[j] = temp;
            }
        }
    }
}
