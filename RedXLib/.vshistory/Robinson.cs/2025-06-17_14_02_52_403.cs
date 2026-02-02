using System.Diagnostics;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;

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

            return null;
        }

        public static BufferStream Decrypt(byte[] ciphertext, REKey keyB)
        {
            // overlay BufferStream over ciphertext
            var cipherStream = new BufferStream(ciphertext);


            return null;


        }

    }

    public class REKey
    {
        internal byte[] key;
        internal byte[][] rkd;
        byte _keySize;
        public REKey(byte keySize = 8)
        {
            //if (keySize < 2)
            //    throw new ArgumentException("Key size must be at least 1", nameof(keySize));
            _keySize = keySize;
            using var keyData = new BufferStream();
            rkd = new byte[keySize][];
            var idx = (short)0;
            for (int i = 0; i < keySize; i++)
            {
                var array = new byte[256];
                for (short a = 0; a < array.Length; a++)
                {
                    array[a] = (byte)a;
                }



                Shuffle(array.AsSpan());

                rkd[i] = new byte[256];
                for (byte j = 0; j < array.Length; j++)
                {
                    rkd[i][array[j]] = j;
                    keyData.Write(array[j]);
                }
            }
            key = keyData.ToArray();
        }

        public BufferStream MapData(ReadOnlySpan<byte> data)
        {
            // Random start location within the key
            int sl = RandomNumberGenerator.GetInt32(0, key.Length);

            var sRow = sl / 256;
            var sCol = sl % 256;

            var output = new BufferStream();
            output.Write((short)sl);

            var curRow = sRow;
            var curCol = sCol;

            for (int i = 0; i < data.Length; i++)
            {
                var curByte = data[i];
                curByte = (byte)((curByte + i) % 256);

                // Look up the column index of curByte in the current row
                var col = rkd[curRow][curByte];

                // Calculate forward distance from curCol to col (0-255, wrapped)
                var dist = col - curCol;
                if (dist < 0)
                    dist += 256;

                // ✅ Write skip value to output
                output.WriteByte((byte)dist);

                // Update cursor
                curCol = col;
                curRow = (curRow + 1) % _keySize;
            }

            output.Position = 0;
            return output;
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
            // Read the initial start location
            var sl = (short)skips.ReadInt16();
            var sRow = sl / 256;
            var sCol = sl % 256;

            var curRow = sRow;
            var curCol = sCol;

            var output = new BufferStream();

            while (skips.Position < skips.Length)
            {
                // Read the next skip value
                byte dist = skips.ReadByte();

                // Advance col by skip distance
                curCol = (curCol + dist) % 256;

                // In the current row, find the byte at curCol
                // Reverse lookup from position → byte
                byte value = 0;
                for (byte b = 0; b < 255; b++)
                {
                    if (rkd[curRow][b] == curCol)
                    {
                        value = b;
                        break;
                    }
                }

                // Reverse the +i transformation
                int i = (int)(output.Length); // # of prior decoded bytes
                value = (byte)((256 + value - i) % 256);

                output.WriteByte(value);

                // Advance row
                curRow = (curRow + 1) % _keySize;
            }

            output.Position = 0;
            return output;
        }

        public BufferStream UnmapData(Memory<byte> skipsSpan)
        {
            return UnmapData(new BufferStream(skipsSpan));
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
