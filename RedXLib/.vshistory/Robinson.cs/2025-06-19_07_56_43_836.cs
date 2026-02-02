using System;
using System.Buffers;
using System.Security.Cryptography;
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

        public static BufferStream Encrypt(byte[] data, REKey key)
        {
            // buffer to hold cipher text

            var ret = new BufferStream();
            var header = new BufferStream();

            var startLocation = (short)RandomNumberGenerator.GetInt32(0, key.key.Length);
            ret.Write7BitInt(startLocation);

            var ivLen = (byte)RandomNumberGenerator.GetInt32(7, 63);
            ret.Write(ivLen);
            //Debug.WriteLine(ivLen, "IV Length");
            var iv = RandomNumberGenerator.GetBytes(ivLen);
            //Debug.WriteLine(BitConverter.ToString(iv), "IV");
            using var headerEnc = key.MapData(iv, ivLen);

            
           

            ret.Write(headerEnc);

            using var cipher = key.MapData(data, startLocation, iv);

            ret.Write(cipher);

            ret.Position = 0;
            return ret;
        }

        public static BufferStream Decrypt(BufferStream ciphertext, REKey key)
        {
            var startLocation = (short)ciphertext.Read7BitInt();
            var ivLen = ciphertext.ReadByte();

            var iv = key.UnmapData(ciphertext, ivLen, default, ivLen);

            var plain = key.UnmapData(ciphertext, startLocation, iv.AsReadOnlySpan);

            plain.Position = 0;
            return plain;
        }

        public static BufferStream Decrypt(byte[] ciphertext, REKey key)
        {
            // overlay BufferStream over ciphertext
            return Decrypt(new BufferStream(ciphertext), key);

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
                for (int j = 0; j < array.Length; j++)
                {
                    rkd[i][array[j]] = (byte)j;
                    keyData.Write(array[j]);
                }
            }
            key = keyData.ToArray();
        }

        public BufferStream MapData(ReadOnlySpan<byte> data, short startLocation, Span<byte> iv = default)
        {
            // wrap startLocation
            startLocation = (short)(startLocation % (_keySize * 256));
            var sRow = startLocation / 256;
            var sCol = startLocation % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            var ivLen = iv.Length;

            //var drbg = new HmacDrbg(SHA3_256.HashData(key), iv);

            var bx = new Blake3XofReader(key, iv);
            

            Span<ushort> randSkip = stackalloc ushort[1];

            for (int i = 0; i < data.Length; i++)
            {
                byte curByte = data[i];
                if (ivLen > 0)
                    curByte = (byte)((curByte + i + iv[i % ivLen]) % 256);

                // 🔁 Step 1: Random jump
                bx.ReadNext(randSkip);
                //drbg.Generate(randSkip);
                short skip = (short)(randSkip[0] & 0x7FFF); // Ensure non-negative
                skip = (short)((skip % (_keySize - 1)) + 1); // Range: [1, _keySize-1]

                curRow = (curRow + skip) % _keySize;

                // 🔁 Step 2: Get position of curByte in new row
                int col = rkd[curRow][curByte];

                // 🔁 Step 3: Calculate wrapped forward distance
                int dist = col - curCol;
                if (dist < 0)
                    dist += 256;

                output.WriteByte((byte)dist);

                // 🔁 Step 4: Advance cursor
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


        /// <summary>
        /// Inverses the skip‐distance mapping performed by MapData.
        /// </summary>
        /// <param name="mapped">Stream returned by MapData (position = 0).</param>
        /// <param name="iv">Same IV span passed into MapData.</param>
        /// <param name="count">
        /// If >0, stop after <paramref name="count"/> bytes (otherwise, until end-of-stream).
        /// </param>
        /// <returns>Recovered plaintext.</returns>
        public BufferStream UnmapData(BufferStream mapped, short startLocation, ReadOnlySpan<byte> iv = default, int count = -1)
        {
            startLocation = (short)(startLocation % (_keySize * 256));
            var sRow = startLocation / 256;
            var sCol = startLocation % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            var ivLen = iv.Length;

            var drbg = new HmacDrbg(SHA3_256.HashData(key), iv);
            var bx = new Blake3XofReader(key, iv);

            Span<ushort> randSkip = stackalloc ushort[1];

            for (int i = 0; (count < 0 || i < count) && mapped.Position < mapped.Length; i++)
            {
                int skipVal = mapped.ReadByte();
                if (skipVal < 0) break;

                bx.ReadNext(randSkip);
                short skip = (short)(randSkip[0] & 0x7FFF);
                skip = (short)((skip % (_keySize - 1)) + 1);

                curRow = (curRow + skip) % _keySize;

                int targetCol = (curCol + skipVal) % 256;
                byte plain = key[curRow * 256 + targetCol];

                if (ivLen > 0)
                    plain = (byte)((256 + plain - i - iv[i % ivLen]) % 256);

                output.WriteByte(plain);
                curCol = targetCol;
                curRow = (curRow + 1) % _keySize;
            }

            output.Position = 0;
            return output;
        }

        public BufferStream UnmapData(Memory<byte> skipsSpan, short startLocation, ReadOnlySpan<byte> iv = default, int count = -1)
        {
            return UnmapData(new BufferStream(skipsSpan), startLocation, iv, count);
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


    namespace RobinsonEncryptionLib.Security
    {

        internal static class BufferWriterExtensions
        {
            public static void Write(this IBufferWriter<byte> writer, ReadOnlySpan<byte> span)
            {
                var memory = writer.GetSpan(span.Length);
                span.CopyTo(memory);
                writer.Advance(span.Length);
            }
        }
    }

}
