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
using System.Numerics;

namespace RobinsonEncryptionLib
{
    public static class RE
    {

        public static REKey CreateKey(byte keySize = 8)
        {
            return new REKey(keySize);
        }

        public static BufferStream Encrypt(byte[] data, REKey key, bool authenticated = false)
        {
            // buffer to hold cipher text

            var ret = new BufferStream();
            var header = new BufferStream();

            var startLocation = (short)RandomNumberGenerator.GetInt32(0, key.key.Length);
            ret.Write7BitInt(startLocation);

            if (authenticated)
                ret.WriteByte(1);
            else
                ret.WriteByte(0);

            var ivLen = (byte)RandomNumberGenerator.GetInt32(7, 64);
            ret.Write(ivLen);


            //Debug.WriteLine(ivLen, "IV Length");
            var iv = RandomNumberGenerator.GetBytes(ivLen);
            //Debug.WriteLine(BitConverter.ToString(iv), "IV");
            using var headerEnc = key.MapData(iv, ivLen);




            ret.Write(headerEnc);

            using var cipher = key.MapData(data, startLocation, iv);

            if (authenticated)
            {
                var b3 = Blake3.Hasher.New();
                b3.Update(cipher.AsReadOnlySpan);
                b3.Update(iv);
                Span<byte> auth = stackalloc byte[32];
                b3.Finalize(auth);
                using var authEnc = key.MapData(auth, ivLen, iv);
                ret.Write(authEnc);

            }

            ret.Write(cipher);

            ret.Position = 0;
            return ret;
        }

        public static BufferStream Decrypt(BufferStream ciphertext, REKey key)
        {
            var startLocation = (short)ciphertext.Read7BitInt();
            var mode = ciphertext.ReadByte();
            var ivLen = ciphertext.ReadByte();

            var iv = key.UnmapData(ciphertext, ivLen, default, ivLen);

            if (mode == 1)
            {
                var auth = key.UnmapData(ciphertext, ivLen, iv.AsReadOnlySpan, 32);
                var b3 = Blake3.Hasher.New();
                b3.Update(ciphertext.ReadonlySliceAtCurrent());
                b3.Update(iv.AsReadOnlySpan);
                Span<byte> auth2 = stackalloc byte[32];
                b3.Finalize(auth2);
                if (auth.AsReadOnlySpan.SequenceEqual(auth2) == false)
                    return null;
            }

            var plain = key.UnmapData(ciphertext, startLocation, iv.AsReadOnlySpan);

            plain.Position = 0;
            return plain;
        }

        public static BufferStream Decrypt(BufferStream ciphertext, REReadOnlyKey key)
        {
            var startLocation = (short)ciphertext.Read7BitInt();
            var mode = ciphertext.ReadByte();
            var ivLen = ciphertext.ReadByte();

            var iv = key.UnmapData(ciphertext, ivLen, default, ivLen);

            if (mode == 1)
            {
                var auth = key.UnmapData(ciphertext, ivLen, iv.AsReadOnlySpan, 32);
                var b3 = Blake3.Hasher.New();
                b3.Update(ciphertext.ReadonlySliceAtCurrent());
                b3.Update(iv.AsReadOnlySpan);
                Span<byte> auth2 = stackalloc byte[32];
                b3.Finalize(auth2);
                if (auth.AsReadOnlySpan.SequenceEqual(auth2) == false)
                    return null;
            }

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

    public class REReadOnlyKey
    {
        private Dictionary<uint, byte> keyMap;
        internal Memory<byte> keyHash;
        private int keyLength;
        private byte keyBlockSize;
        internal Memory<byte> seed;
        private Dictionary<(uint, ushort), byte> chMap;
        private Memory<byte> chPublicParam;

        public REReadOnlyKey(REKey key, SmallPrimeChameleon ch)
        {
            // This assigns the total number of bytes in the REKey (i.e., key.key.Length) to the REReadOnlyKey's internal field keyLength.
            keyLength = key.keyLength;

            // This assigns the keyBlockSize (number of 256-byte key rows) from the original REKey into the REReadOnlyKey.
            keyBlockSize = key.keyBlockSize;


            // ← same as the default REReadOnlyKey ctor: hash the full key  
            var b3 = Blake3.Hasher.New();
            b3.Update(key.key.AsSpan());
            var fullHash = new byte[64];
            b3.Finalize(fullHash);
            keyHash = fullHash;                                      // store it if you still need the 64-byte digest
            seed = keyHash.Slice(0, 32);                          // first 32 bytes → Blake3 keyed mode key


            chMap = new Dictionary<(uint, ushort), byte>(keyLength);

            var rnd = RandomNumberGenerator.Create();
            Span<byte> temp = stackalloc byte[2];
            Span<byte> hashBytes = stackalloc byte[4];
            ushort r = 0;
            uint hash = 0;

            for (int i = 0; i < key.keyLength; i++)
            {

                do
                {
                    rnd.GetBytes(temp);
                    r = MemoryMarshal.Read<ushort>(temp);
                    ch.Compute(i, r, hashBytes);
                    hash = MemoryMarshal.Read<uint>(hashBytes);
                }
                while (!chMap.TryAdd((hash, r), key.key[i]));
            }

            // Store the CH PublicParam
            chPublicParam = ch.PublicParam;


        }


        private struct KeyMapEntry
        {
            public uint hash;
            public byte value;
        }

        public REReadOnlyKey(Span<byte> rok)
        {
            if (rok.Length < 1)
                throw new ArgumentException("Invalid ROK data: too short");

            var rokBuff = new BufferStream(rok);

            var keyHashSize = rokBuff.ReadByte();
            if (rok.Length < 1 + keyHashSize)
                throw new ArgumentException("Invalid ROK data: missing key hash");

            keyHash = rokBuff.ReadBytes(keyHashSize);

            keyMap = new Dictionary<uint, byte>();


            keyLength = (int)((rokBuff.Length - 1 - keyHashSize) / 5);
            keyBlockSize = (byte)(keyLength / 256);

            while (rokBuff.Position < rokBuff.Length)
            {
                var hash = rokBuff.ReadUInt32();
                var value = rokBuff.ReadByte();
                if (!keyMap.TryAdd(hash, value))
                    throw new Exception("Failed to map key");
            }
        }
        public byte[] ToBytes()
        {
            var retBuff = new BufferStream();

            retBuff.WriteByte((byte)keyHash.Length);
            retBuff.Write(keyHash.Span);

            Span<uint> kTemp = stackalloc uint[1];
            Span<byte> bTemp = MemoryMarshal.Cast<uint, byte>(kTemp);
            foreach (var kv in keyMap.OrderBy(x => x.Value))
            {
                // using span, write key to ret
                //kTemp[0] = kv.Key;
                retBuff.Write(kv.Key);
                retBuff.WriteByte(kv.Value);
            }
            return retBuff;
        }

        public BufferStream UnmapData(BufferStream mapped, short startLocation, ReadOnlySpan<byte> iv = default, int count = -1)
        {
            startLocation = (short)(startLocation % (keyBlockSize * 256));
            var sRow = startLocation / 256;
            var sCol = startLocation % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            var ivLen = iv.Length;

            var bx = new Blake3XofReader(keyHash.Span, iv);
            var bh = Blake3.Hasher.New();

            Span<ushort> randSkipArrayOfOne = stackalloc ushort[1];

            Span<int> iTemp = stackalloc int[1];
            Span<byte> bTemp = MemoryMarshal.Cast<int, byte>(iTemp);

            for (int i = 0; (count < 0 || i < count) && mapped.Position < mapped.Length; i++)
            {
                int skipVal = mapped.ReadByte();
                if (skipVal < 0) break;


                bx.ReadNext(randSkipArrayOfOne);
                var rowJump = ((randSkipArrayOfOne[0] % keyLength) / 256);
                var colJump = randSkipArrayOfOne[0] % 256;


                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) % 256;

                int keyIndex = curRow * 256 + (curCol + skipVal) % 256;
                iTemp[0] = keyIndex;
                bh.Reset();
                bh.Update(keyHash.Span);
                bh.Update(bTemp);

                var hash = bh.Finalize().AsSpan();
                byte plain = 0;

                var hash32 = 0u; // MemoryMarshal.Read<uint>(hash);
                for (int offset = 0; offset <= 28; offset++)
                {
                    hash32 = MemoryMarshal.Read<uint>(hash.Slice(offset, 4));
                    if (keyMap.TryGetValue(hash32, out plain))
                    {
                        break;
                    }
                    else if (offset == 28)
                        return null;
                }


                if (ivLen > 0)
                    plain = (byte)((256 + plain - i - iv[i % ivLen]) % 256);

                curCol = (curCol + skipVal) % 256;
                curRow = (curRow + 1) % keyBlockSize;

                output.WriteByte(plain);
            }

            output.Position = 0;
            return output;
        }

        static public REReadOnlyKey FromBytes(byte[] keyBytes)
        {
            return new REReadOnlyKey(keyBytes);
        }

    }

    public class REKey
    {
        internal byte[] key;
        internal byte[][] rkd;
        internal int keyLength;
        private Memory<byte> keyHash;

        internal byte keyBlockSize;
        public REKey(byte keySize = 8)
        {
            //if (keySize < 2)
            //    throw new ArgumentException("Key size must be at least 1", nameof(keySize));
            this.keyBlockSize = keySize;
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
            keyLength = key.Length;

            var b3 = Blake3.Hasher.New();
            b3.Update(key.AsSpan());
            keyHash = new byte[64];
            b3.Finalize(keyHash.Span);


        }

        public REReadOnlyKey CreateReadOnlyKey()
        {
            Span<byte> tdBuf = stackalloc byte[4];
            RandomNumberGenerator.Fill(tdBuf);
            uint trapdoor = MemoryMarshal.Read<uint>(tdBuf);
            var ch = SmallPrimeChameleon.CreateWithTrapdoor(trapdoor, keyLength);
            return new REReadOnlyKey(this, ch);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream MapData(ReadOnlySpan<byte> data, short startLocation, Span<byte> iv = default)
        {
            // wrap startLocation
            startLocation = (short)(startLocation % keyLength);
            var sRow = startLocation / 256 % keyBlockSize;
            var sCol = startLocation % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            var ivLen = iv.Length;


            var bx = new JumpGenerator(key, 1, iv);


            ushort randSkipArrayOfOne = 0;
            byte curByte = 0;
            for (int i = 0; i < data.Length; i++)
            {
                curByte = data[i];
                if (ivLen > 0)
                    curByte = (byte)((curByte + i + iv[i % ivLen]) % 256);

                // 🔁 Step 1: Random jump
                randSkipArrayOfOne = bx.NextJump16();
                var rowJump = ((randSkipArrayOfOne % keyLength) / 256);
                var colJump = randSkipArrayOfOne % 256;

                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) % 256;

                // 🔁 Step 2: Get position of curByte in new row
                int col = rkd[curRow][curByte];

                // 🔁 Step 3: Calculate wrapped forward distance
                int dist = col - curCol;
                if (dist < 0)
                    dist += 256;

                output.WriteByte((byte)dist);

                // 🔁 Step 4: Advance cursor
                curCol = col;
                curRow = (curRow + 1) % keyBlockSize;
            }

            output.Position = 0;
            return output;
        }
        public BufferStream MapData(REReadOnlyKey rok, ReadOnlySpan<byte> data, short startLocation, Span<byte> iv = default)
        {
            // wrap startLocation
            startLocation = (short)(startLocation % keyLength);
            var sRow = startLocation / 256 % keyBlockSize;
            var sCol = startLocation % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            var ivLen = iv.Length;


            var bx = new JumpGenerator(rok.keyHash.Span, 1, iv);

            ushort randSkipArrayOfOne = 0;

            for (int i = 0; i < data.Length; i++)
            {
                byte curByte = data[i];
                if (ivLen > 0)
                    curByte = (byte)((curByte + i + iv[i % ivLen]) % 256);

                // 🔁 Step 1: Random jump
                randSkipArrayOfOne = bx.NextJump16();
                var rowJump = ((randSkipArrayOfOne % keyLength) / 256);
                var colJump = randSkipArrayOfOne % 256;

                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) % 256;

                // 🔁 Step 2: Get position of curByte in new row
                int col = rkd[curRow][curByte];

                // 🔁 Step 3: Calculate wrapped forward distance
                int dist = col - curCol;
                if (dist < 0)
                    dist += 256;

                output.WriteByte((byte)dist);

                // 🔁 Step 4: Advance cursor
                curCol = col;
                curRow = (curRow + 1) % keyBlockSize;
            }

            output.Position = 0;
            return output;
        }






        // suppressed for now and unused
        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        //static byte CalcRotation(int distance)
        //{
        //    uint d = (uint)distance;
        //    d ^= d >> 3;
        //    d ^= d << 5;
        //    d ^= d >> 7;
        //    byte rot = (byte)((d * 0xA3) & 0xFF); // Multiplicative scrambling
        //    return rot == 0 ? (byte)1 : rot; // Avoid zero
        //}


        /// <summary>
        /// Inverses the skip‐distance mapping performed by MapData.
        /// </summary>
        /// <param name="mapped">Stream returned by MapData (position = 0).</param>
        /// <param name="iv">Same IV span passed into MapData.</param>
        /// <param name="count">
        /// If >0, stop after <paramref name="count"/> bytes (otherwise, until end-of-stream).
        /// </param>
        /// <returns>Recovered plaintext.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapData(BufferStream mapped, short startLocation, ReadOnlySpan<byte> iv = default, int count = -1)
        {
            startLocation = (short)(startLocation % (keyBlockSize * 256));
            var sRow = startLocation / 256;
            var sCol = startLocation % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            var ivLen = iv.Length;

            var bx = new Blake3XofReader(keyHash.Span, iv);

            Span<ushort> randSkipArrayOfOne = stackalloc ushort[1];

            for (int i = 0; (count < 0 || i < count) && mapped.Position < mapped.Length; i++)
            {
                int skipVal = mapped.ReadByte();
                if (skipVal < 0) break;

                bx.ReadNext(randSkipArrayOfOne);
                var rowJump = ((randSkipArrayOfOne[0] % keyLength) / 256);
                var colJump = randSkipArrayOfOne[0] % 256;

                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) % 256;

                byte plain = key[curRow * 256 + (curCol + skipVal) % 256];

                if (ivLen > 0)
                    plain = (byte)((256 + plain - i - iv[i % ivLen]) % 256);

                curCol = (curCol + skipVal) % 256;
                curRow = (curRow + 1) % keyBlockSize;

                output.WriteByte(plain);
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
}
