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

    public sealed class REReadOnlyKey
    {
        private readonly int keyLength;
        private readonly int keyBlockSize;
        internal readonly Memory<byte> keyHash;        // 64-byte Blake3 digest
        private readonly Memory<ushort> nonces;         // ← NEW: one nonce per flat index
        private readonly Dictionary<uint, byte> chMap;
        private readonly byte[] chPublicParam;  // if you’re using ch-hash
        private readonly SmallPrimeChameleon ch;

        // ctor for chameleon-hash mode
        public REReadOnlyKey(REKey key, SmallPrimeChameleon ch)
        {
            keyLength = key.keyLength;
            keyBlockSize = key.keyBlockSize;
            this.ch = ch;

            // 1) compute full-key Blake3 hash → keyHash
            keyHash = new byte[64];
            {
                var b3 = Blake3.Hasher.New();
                b3.Update(key.key.AsSpan());
                b3.Finalize(keyHash.Span);
            }

            // 2) allocate nonce array and map
            nonces = new ushort[keyLength];
            chMap = new Dictionary<uint, byte>(keyLength);

            // 3) fill map: choose a fresh nonce for each slot i
            Span<byte> rndBuf = stackalloc byte[2];  // for RNG
            Span<byte> hashBuf = stackalloc byte[4];  // for ch.Compute output
            for (int i = 0; i < keyLength; i++)
            {
                ushort r;
                uint h32;
                do
                {
                    // 3a) pick a random nonce
                    RandomNumberGenerator.Fill(rndBuf);
                    r = MemoryMarshal.Read<ushort>(rndBuf);

                    // 3b) compute the 32-bit chameleon hash into hashBuf
                    ch.Compute(i, r, hashBuf);
                    h32 = MemoryMarshal.Read<uint>(hashBuf);
                }
                while (chMap.ContainsKey(h32));

                nonces.Span[i] = r;
                chMap[h32] = key.key[i];
            }

            // 4) stash public params for anyone needing to re-Compute
            chPublicParam = ch.PublicParam;
        }

        // ——————————————————————————————————————————————
        // decryption
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapData(BufferStream mapped, short startLocation, ReadOnlySpan<byte> iv = default, int count = -1)
        {
            // keyLength is keyBlockSize * 256
            startLocation = (short)(startLocation % this.keyLength);
            int curRow = startLocation / 256;
            int curCol = startLocation % 256;
            int ivLen = iv.Length;
            int keyLength = this.keyLength;
            int blockSz = keyBlockSize;

            var output = new BufferStream();
            var bx = new JumpGenerator(keyHash.Span, 1, iv);
            var chPubLocal = ch;
            var noncesSpan = nonces.Span;
            var map = chMap;
            Span<byte> hashBuf = stackalloc byte[4];
            var streamLength = mapped.Length;             // avoid repeated property access
            var streamPos = mapped.Position;

            for (int i = 0; (count < 0 || i < count) && streamPos < streamLength; i++)
            {
                int dist = mapped.ReadByte();
                if (dist < 0) break;
                streamPos++;

                // replay skip
                ushort skip = bx.NextJump16();
                // since keyLength == keyBlockSize * 256, and skip < keyLength:
                int colJump = skip & 0xFF;
                int rowJump = (skip >> 8) % keyBlockSize;
                curCol = (curCol + colJump) & 0xFF;

                // recover index
                int newCol = (curCol + dist) & 0xFF;
                int flatIndex = curRow * 256 + newCol;

                // ch-hash lookup
                ushort r = noncesSpan[flatIndex];
                chPubLocal.Compute(flatIndex, r, hashBuf);
                uint h32 = MemoryMarshal.Read<uint>(hashBuf);

                if (!map.TryGetValue(h32, out byte plain))
                    throw new CryptographicException($"ROK lookup failed at index {flatIndex}");

                // undo IV
                if (ivLen > 0)
                    plain = (byte)((256 + plain - i - iv[i % ivLen]) % 256);

                output.WriteByte(plain);

                // advance
                curCol = newCol;
                curRow = (curRow + 1) % blockSz;
            }

            output.Position = 0;
            return output;
        }


        /// <summary>
        /// Returns the key as a persistable byte array with the following format:<br/>
        /// [keyHashLength:int32][keyHash: byte[keyHashLength]][publicParam: byte[4]][nonces: ushort[keyLen]][chMapKeys: uint[keyLen]]
        /// </summary>
        /// <returns></returns>
        public byte[] ToBytes()
        {
            int hashLen = keyHash.Length;           // e.g. 64
            int entryCount = keyLength;                // nonces + h32 pairs
            int total = 4                           // hashLen int
                      + hashLen
                      + chPublicParam.Length       // fixed 4
                      + entryCount * (2 + 4);      // ushort + uint per entry

            var blob = new byte[total];
            int off = 0;

            // 1) keyHashLength (int)
            MemoryMarshal.Write(blob.AsSpan(off, 4), ref hashLen);
            off += 4;

            // 2) keyHash bytes
            keyHash.Span.CopyTo(blob.AsSpan(off, hashLen));
            off += hashLen;

            // 3) publicParam (4 bytes)
            Buffer.BlockCopy(chPublicParam, 0, blob, off, chPublicParam.Length);
            off += chPublicParam.Length;

            // 4) nonces[] (ushort each)
            var ns = nonces.Span;
            for (int i = 0; i < entryCount; i++)
            {
                ushort r = ns[i];
                MemoryMarshal.Write(blob.AsSpan(off, 2), ref r);
                off += 2;
            }

            // 5) chMap keys in plaintext order (bucket 0x00…0xFF)
            int blk = keyBlockSize;
            var buckets = new List<uint>[256];
            for (int b = 0; b < 256; b++)
                buckets[b] = new List<uint>(blk);
            foreach (var kv in chMap)
                buckets[kv.Value].Add(kv.Key);

            for (int p = 0; p < 256; p++)
            {
                foreach (uint h32 in buckets[p])
                {
                    MemoryMarshal.Write(blob.AsSpan(off, 4), h32);
                    off += 4;
                }
            }

            return blob;
        }

        /// <summary>
        /// Rehydrate directly from the ToBytes() blob.
        /// </summary>
        public REReadOnlyKey(ReadOnlySpan<byte> blob)
        {
            int off = 0;

            // 1) hashLen
            int hashLen = MemoryMarshal.Read<int>(blob.Slice(off, 4));
            off += 4;

            // 2) keyHash
            var hashArr = blob.Slice(off, hashLen).ToArray();
            keyHash = new Memory<byte>(hashArr);
            off += hashLen;

            // 3) publicParam (4 bytes)
            chPublicParam = blob.Slice(off, 4).ToArray();
            off += 4;

            // 4) remaining bytes = entryCount*(2+4)
            int remaining = blob.Length - off;
            int entryCount = remaining / 6;
            keyLength = entryCount;
            keyBlockSize = keyLength / 256;

            // 5) nonces[]
            var nonceArr = new ushort[keyLength];
            for (int i = 0; i < keyLength; i++)
            {
                nonceArr[i] = MemoryMarshal.Read<ushort>(blob.Slice(off, 2));
                off += 2;
            }
            nonces = new Memory<ushort>(nonceArr);

            // 6) h32 array
            var h32Arr = new uint[keyLength];
            for (int i = 0; i < keyLength; i++)
            {
                h32Arr[i] = MemoryMarshal.Read<uint>(blob.Slice(off, 4));
                off += 4;
            }

            // 7) rebuild chMap by grouping every keyBlockSize entries per byte
            chMap = new Dictionary<uint, byte>(keyLength);
            for (int i = 0; i < keyLength; i++)
            {
                byte plain = (byte)(i / keyBlockSize);
                chMap[h32Arr[i]] = plain;
            }

            // 8) recreate public-only chameleon
            ch = SmallPrimeChameleon.CreateFromPublicParam(chPublicParam, keyLength);
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
