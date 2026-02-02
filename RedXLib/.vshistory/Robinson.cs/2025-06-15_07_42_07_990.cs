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
            // do first round transform of data thru keyA
            var t1 = keyA.DrawPath(data);

            var outBuf = new BufferStream();


            return null;
        }

        public static byte[] Decrypt(byte[] cipher, REKey keyA, REKey keyB)
        {
            return null;

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

        public (BufferStream skips, Dictionary<byte, short> kStar) DrawPath(ReadOnlySpan<byte> data)
        {
            var sl = RandomNumberGenerator.GetInt32(0, key.Length);
            var skips = new BufferStream();
            var kStar = new Dictionary<byte, short>();

            skips.Write((short)sl);
            var curPos = sl;
            for (int i = 0; i < data.Length; i++)
            {
                var indexes = rkd[key.Span[data[i]]];
                // find the shortest distance, pos or neg, to one of the indexes from the current position, then update current position
                var min = Math.Abs(indexes[0] - curPos);
                var minIndex = 0;
                for (int j = 1; j < indexes.Length; j++)
                {
                    var cur = Math.Abs(indexes[j] - curPos);
                    if (cur < min)
                    {
                        min = cur;
                        minIndex = j;
                    }
                }

                // Calculate the relative skip distance, considering wrap-around
                var skipDistance = (short)(indexes[minIndex] - curPos);
                if (skipDistance > key.Length / 2)
                {
                    skipDistance -= (short)key.Length;
                }
                else if (skipDistance < -key.Length / 2)
                {
                    skipDistance += (short)key.Length;
                }
                System.Diagnostics.Debug.WriteLine(skipDistance, "skipDistance");
                skips.Write((byte)skipDistance); // Write the relative skip distance
                curPos = indexes[minIndex]; // Update the current position

                kStar[data[i]] = indexes[minIndex];
            }

            return (skips, kStar);
        }


        public byte[] FollowPath(BufferStream skips, Dictionary<byte, short> kStar)
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
                    short skip = skips.ReadInt16();

                    // Apply the skip to the current position, handling wrap-around
                    currentPos = (short)((currentPos + skip + key.Length) % key.Length);

                    // Get the byte at this position in the key
                    byte keyByte = key.Span[currentPos];

                    // Find the data byte corresponding to this key byte using kStar
                    foreach (var kv in kStar)
                    {
                        if (kv.Value == currentPos)
                        {
                            result.Add(kv.Key);
                            break;
                        }
                    }
                }
                catch (EndOfStreamException)
                {
                    // We've reached the end of the stream
                    break;
                }
            }

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
