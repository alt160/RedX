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

        public static REKey CreateKey()
        {
            return new REKey();
        }

        public static byte[] Encrypt(byte[] data, REKey keyA, REKey keyB)
        {
            // buffer to hold cipher text
            var outBuf = new BufferStream();

            // do first round transform of data thru keyA
            var dataMappedByKeyA = keyA.CreateDataMap(data);

            // encrypted data with keyB
            var dataMappedByKeyB = keyB.CreateDataMap(dataMappedByKeyA.skips.AsReadOnlySpan);

            // put dataMappedByKeyA kStar into a buffer
            var kStarBuffer = new BufferStream();
            foreach (var kv in dataMappedByKeyA.kStar)
            {
                kStarBuffer.Write(kv.Key);
                kStarBuffer.Write(kv.Value);
            }
            // encrypt kStar with keyB
            kStarBuffer.Position = 0;
            var aStarMappedByKeyB = keyB.CreateDataMap(kStarBuffer.AsReadOnlySpan);

            // create random length prefix of random bytes
            var prefix = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(17, 64));

            // write prefix length, prefix, aStar, and mapped data to outBuf
            // Encrypted payload structure:
            // [prefixLength:1][prefix:N][aStarLength:7bit][aStarMapped][dataMappedByKeyA]
            outBuf.Write((byte)prefix.Length);
            outBuf.WriteBytes(prefix);
            outBuf.Write7BitEncodedInt((int)aStarMappedByKeyB.skips.Length);
            aStarMappedByKeyB.skips.CopyTo(outBuf);
            dataMappedByKeyA.skips.CopyTo(outBuf);

            // encrypt outBuf with keyB
            var outBufMappedByKeyB = keyB.CreateDataMap(outBuf.AsReadOnlySpan);
            Debug.WriteLine(outBufMappedByKeyB.skips.Length, "outBufMappedByKeyB length");
            // calc sha256 of outBuf
            var prefixSha256 = SHA256.HashData(outBufMappedByKeyB.skips);
            Debug.WriteLine(BitConverter.ToString(prefixSha256), "hash");

            // encrypt hash with keyB
            var encryptedHash = keyB.CreateDataMap(prefixSha256.AsSpan());
            Debug.WriteLine(encryptedHash.skips.Length, "encrypted hash length");

            // final buffer
            var finalBuf = new BufferStream();
            finalBuf.Write7BitEncodedInt((int)encryptedHash.skips.Length);
            finalBuf.Write(encryptedHash.skips);
            finalBuf.Write(outBufMappedByKeyB.skips);

            return finalBuf.ToArray();
        }

        public static byte[] Decrypt(byte[] ciphertext, REKey keyB)
        {
            // overlay BufferStream over ciphertext
            var cipherStream = new BufferStream(ciphertext);

            // read encrypted hash length
            var hashLength = cipherStream.Read7BitEncodedInt();

            // read encrypted hash as slice
            var hash = keyB.UnmapData(cipherStream.ReadBytes(hashLength));

            var computedHash = SHA256.HashData(cipherStream.SegmentAtCurrent());

            // check hash
            if (!hash.SequenceEqual(computedHash))
                return null;

            // decrypt thru keyB
            var decryptedPayload = keyB.UnmapData(cipherStream.SegmentAtCurrent());

            var decryptedStream = new BufferStream(decryptedPayload);
            // read prefix length
            var prefixLength = decryptedStream.Read7BitEncodedInt();

            // skip prefix
            decryptedStream.Position += prefixLength;

            // read aStar length
            var aStarLength = decryptedStream.Read7BitEncodedInt();

            var aStar = new Dictionary<short, byte>();
            for (int i = 0; i < aStarLength; i++)
            {
                aStar[decryptedStream.ReadInt16()] = decryptedStream.ReadByte();
            }

            // decrypt ciphertext with aStar
            var plainText = keyB.UnmapData(decryptedStream, aStar);

            return plainText;


        }

    }

    public class REKey
    {
        internal Memory<byte> key;
        internal Dictionary<byte, short[]> rkd;

        public REKey(byte keySize = 8)
        {
            if (keySize < 2)
                throw new ArgumentException("Key size must be at least 2", nameof(keySize));
            using var keyData = new BufferStream();
            rkd = new Dictionary<byte, short[]>(keySize * 256);

            var idx = (short)0;
            for (int i = 0; i < keySize; i++)
            {
                var array = new byte[256];
                var span = array.AsSpan();
                for (short a = 0; a < span.Length; a++)
                {
                    if (i == 0) rkd[(byte)a] = new short[keySize];
                    span[a] = (byte)a;
                }



                Shuffle(array.AsSpan());

                if (i == 0)
                    for (int j = 0; j < span.Length; j++)
                    {
                        rkd[span[j]][i] = idx++;
                        keyData.Write(span[j]);
                    }
                else
                {
                    // loop thru span starting at the first byte after the byte that has the same value as the last byte of keyData, wrapping around if necessary
                    // Find the starting position based on the last byte of keyData
                    int startPos = span.IndexOf(keyData.ReadLastOf<byte>());

                    if (startPos != -1) // Ensure the byte was found in the span
                    {
                        // Start the loop from the next position after startPos, wrapping around if necessary
                        for (int j = 1; j <= span.Length; j++)
                        {
                            int index = (startPos + j) % span.Length; // Wrap around using modulo
                            rkd[span[index]][i] = idx++;
                            keyData.Write(span[index]);
                        }
                    }
                }
            }
            key = keyData.ToArray();
        }

        public (BufferStream skips, Dictionary<short, byte> kStar) CreateDataMap(ReadOnlySpan<byte> data)
        {
            int sl = RandomNumberGenerator.GetInt32(0, key.Length);
            var skips = new BufferStream();
            var kStar = new Dictionary<short, byte>();
            skips.Write((short)sl);
            int curPos = sl;

            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                var indexes = rkd[key.Span[b]];
                int bestFwd = int.MaxValue, bestFwdJ = 0;
                int bestBwd = int.MaxValue, bestBwdJ = 0;

                for (int j = 0; j < indexes.Length; j++)
                {
                    int idx = indexes[j];
                    if (idx == curPos)
                        continue;
                    int fwd = (idx - curPos + key.Length) % key.Length;
                    int bwd = (curPos - idx + key.Length) % key.Length;

                    if (fwd < bestFwd)
                    {
                        bestFwd = fwd;
                        bestFwdJ = j;
                    }
                    if (bwd < bestBwd)
                    {
                        bestBwd = bwd;
                        bestBwdJ = j;
                    }
                }

                short skipDistance;
                int chosenIdx;
                if (bestFwd < 256)
                {
                    skipDistance = (short)bestFwd;
                    chosenIdx = indexes[bestFwdJ];
                }
                else
                {
                    skipDistance = (short)-bestBwd;
                    chosenIdx = indexes[bestBwdJ];
                }

                if (skipDistance < 0)
                {
                    skips.Write((byte)0);
                    skips.Write((byte)-skipDistance);
                }
                else
                    skips.Write((byte)skipDistance);

                curPos = chosenIdx;
                kStar[(short)chosenIdx] = b;
                Debug.WriteLine($"{b}={chosenIdx}", "kStar Value: ");
            }
            Debug.WriteLine("");
            Debug.WriteLine("");
            return (skips, kStar);
        }



        public byte[] UnmapData(BufferStream skips)
        {
            var result = new List<byte>();
            skips.Position = 0;

            // pivot rkd swapping key for value
            var kStar = new Dictionary<short, byte>();
            foreach (var kv in rkd)
            {
                foreach (var v in kv.Value)
                {
                    kStar[v] = kv.Key;
                }
            }

            // Read the starting position from skips
            short currentPos = skips.ReadInt16();

            // Follow the skip distances until we reach the end of the stream
            while (skips.Position < skips.Length)
            {
                try
                {
                    // Read the next skip distance
                    short skip = skips.ReadByte();
                    if (skip == 0)
                        skip = (short)(skips.ReadByte() * -1);

                    // Apply the skip to the current position, handling wrap-around
                    currentPos = (short)((currentPos + skip + key.Length) % key.Length);

                    System.Diagnostics.Debug.Write((char)kStar[currentPos]);
                    // Find the data byte corresponding to this key byte using kStar
                    result.Add(kStar[currentPos]);
                }
                catch (EndOfStreamException)
                {
                    // We've reached the end of the stream
                    break;
                }
            }
            System.Diagnostics.Debug.WriteLine("");
            return result.ToArray();
        }
        public byte[] UnmapData(Memory<byte> skipsSpan)
        {
            var result = new List<byte>();
            var skips = new BufferStream(skipsSpan);
            skips.Position = 0;

            // pivot rkd swapping key for value
            var kStar = new Dictionary<short, byte>();
            foreach (var kv in rkd)
            {
                foreach (var v in kv.Value)
                {
                    kStar[v] = kv.Key;
                }
            }

            // Read the starting position from skips
            short currentPos = skips.ReadInt16();

            // Follow the skip distances until we reach the end of the stream
            while (skips.Position < skips.Length)
            {
                try
                {
                    // Read the next skip distance
                    short skip = skips.ReadByte();
                    if (skip == 0)
                        skip = (short)(skips.ReadByte() * -1);

                    // Apply the skip to the current position, handling wrap-around
                    currentPos = (short)((currentPos + skip + key.Length) % key.Length);

                    System.Diagnostics.Debug.Write((char)kStar[currentPos]);
                    // Find the data byte corresponding to this key byte using kStar
                    result.Add(kStar[currentPos]);
                }
                catch (EndOfStreamException)
                {
                    // We've reached the end of the stream
                    break;
                }
            }
            System.Diagnostics.Debug.WriteLine("");
            return result.ToArray();
        }
        public byte[] UnmapData(BufferStream skips, Dictionary<short, byte> kStar)
        {
            var result = new List<byte>();
            skips.Position = 0;


            // Read the starting position from skips
            short currentPos = skips.ReadInt16();

            // Follow the skip distances until we reach the end of the stream
            while (skips.Position < skips.Length)
            {
                try
                {
                    // Read the next skip distance
                    short skip = skips.ReadByte();
                    if (skip == 0)
                        skip = (short)(skips.ReadByte() * -1);

                    // Apply the skip to the current position, handling wrap-around
                    currentPos = (short)((currentPos + skip + key.Length) % key.Length);

                    System.Diagnostics.Debug.Write((char)kStar[currentPos]);
                    // Find the data byte corresponding to this key byte using kStar
                    result.Add(kStar[currentPos]);
                }
                catch (EndOfStreamException)
                {
                    // We've reached the end of the stream
                    break;
                }
            }
            System.Diagnostics.Debug.WriteLine("");
            return result.ToArray();
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
