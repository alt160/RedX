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

namespace RedxLib
{
    public static class RE
    {

        // Helper struct returned by header parser for ROK-protected ciphertexts
        private sealed class ReadOnlyHeader
        {
            public short StartLocation { get; set; }
            public byte[] RokLock { get; set; }
            public List<byte[]> Proofs { get; set; }
            public byte[] Iv { get; set; }
            public BufferStream AuthEnc { get; set; }
        }

        // Parse the ROK-protected header (startLocation, rokLock, optional proofs, iv, auth)
        // Returns null on parse or integrity failure. The provided stream's position
        // will be advanced to the start of ciphertext bytes on success.
        private static ReadOnlyHeader ParseReadOnlyHeader(BufferStream bs, REReadOnlyKey rok, int proofPlainSize)
        {
            try
            {
                var startLocation = (short)bs.Read7BitInt();
                var rokLock = bs.ReadBytes(4);

                // Probe and read encrypted proof-count + proofs if present
                int proofCount = 0;
                var proofs = new List<byte[]>();
                var probe = new BufferStream(bs.ToArray());
                probe.Position = bs.Position;
                bool probeOk = false;
                try
                {
                    var cntProbe = rok.UnmapData(probe, (short)0, rokLock, default, 4);
                    if (cntProbe != null && cntProbe.Length == 4)
                    {
                        int pc = MemoryMarshal.Read<int>(cntProbe.AsReadOnlySpan);
                        if (pc >= 0 && pc <= 1024)
                        {
                            proofCount = pc;
                            probeOk = true;
                        }
                    }
                }
                catch
                {
                    probeOk = false;
                }

                if (probeOk)
                {
                    // consume encrypted count
                    var cntEnc = rok.UnmapData(bs, (short)0, rokLock, default, 4);
                    for (int i = 0; i < proofCount; i++)
                    {
                        var p = rok.UnmapData(bs, (short)0, rokLock, default, proofPlainSize);
                        proofs.Add(p.ToArray());
                    }
                }

                // iv header
                var ivLen = bs.ReadByte();
                var iv = rok.UnmapData(bs, (short)ivLen, rokLock, default, ivLen).ToArray();

                // auth tag (encrypted)
                var authEnc = rok.UnmapData(bs, (short)ivLen, rokLock, iv.AsSpan(), 32);

                // verify auth tag using remaining ciphertext bytes
                var b3 = Blake3.Hasher.New();
                b3.Update(bs.ReadonlySliceAtCurrent());
                b3.Update(iv.AsSpan());
                Span<byte> auth2 = stackalloc byte[32];
                b3.Finalize(auth2);
                if (!authEnc.AsReadOnlySpan.SequenceEqual(auth2))
                    return null;

                return new ReadOnlyHeader
                {
                    StartLocation = startLocation,
                    RokLock = rokLock,
                    Proofs = proofs,
                    Iv = iv,
                    AuthEnc = authEnc
                };
            }
            catch
            {
                return null;
            }
        }

        // Domain separator for VRF transcripts (kept as byte[] to avoid span field restrictions)
        private static readonly byte[] VrfDomainBytes = new byte[] { (byte)'R', (byte)'E', (byte)'D', (byte)'X', (byte)'_', (byte)'V', (byte)'R', (byte)'F', (byte)'_', (byte)'C', (byte)'H', (byte)'U', (byte)'N', (byte)'K', (byte)'_', (byte)'V', (byte)'1' };

        // default chunk size (cipherbytes)
        private const int DefaultAuthorityChunkSize = 4096;
        // default fixed proof size (bytes) for per-chunk VRF proofs stored encrypted.
        private const int DefaultProofPlainSize = 96;


        public static REKey CreateKey(byte keySize = 8)
        {
            return new REKey(keySize);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ComputeH32(ReadOnlySpan<byte> keyHash, int index, ushort nonce)
        {
            // Build a 64-bit input: keyHash (first 16 bytes) || index (4) || nonce (2)
            // Use Blake3 to derive a 32-bit value. This replaces the chameleon hash
            // and ensures the lookup depends on the key material.
            Span<byte> buf = stackalloc byte[8 + 4 + 2]; // small buffer
            // absorb a short portion of keyHash to bind to the master key
            for (int i = 0; i < 8; i++) buf[i] = keyHash[i];
            MemoryMarshal.Write(buf.Slice(8, 4), ref index);
            MemoryMarshal.Write(buf.Slice(12, 2), ref nonce);

            var h = Blake3.Hasher.New();
            h.Update(buf);
            Span<byte> out4 = stackalloc byte[4];
            h.Finalize(out4);
            return MemoryMarshal.Read<uint>(out4);
        }

        public static BufferStream Encrypt(byte[] data, REKey key)
        {
            return EncryptWithAuthority(data, key, null, null, DefaultProofPlainSize);
        }

        /// <summary>
        /// Encrypt with optional authority proofs. Authority proofs are provided as a list
        /// of fixed-length plaintext blobs. They are stored encrypted immediately after the
        /// per-message rokLock. The count is stored as a 4-byte little-endian encrypted value
        /// encrypted such that the ROK holder can decrypt the proofs (use the provided rokTarget).
        /// </summary>
        public static BufferStream EncryptWithAuthority(byte[] data, REKey key, REReadOnlyKey rokTarget, IList<byte[]> authorityProofs, int proofPlainSize = DefaultProofPlainSize)
        {
            // buffer to hold cipher text
            var ret = new BufferStream();

            // 1) pick a random start location
            var startLocation = (short)RandomNumberGenerator.GetInt32(0, key.key.Length);
            ret.Write7BitInt(startLocation);

            // 2) generate & write per-message 4-byte seed
            var rokLockBytes = RandomNumberGenerator.GetBytes(4);
            ret.Write(rokLockBytes);
            //Console.WriteLine($"[EncryptWithAuthority] rokLock (hex): {BitConverter.ToString(rokLockBytes)}");

            // 3) write encrypted proof count and proofs (if any) using mapping that ROK can unmap
            int proofCount = authorityProofs?.Count ?? 0;
            Span<byte> cntBuf = stackalloc byte[4];
            MemoryMarshal.Write(cntBuf, ref proofCount);
            if (proofCount > 0)
            {
                if (rokTarget == null)
                    throw new ArgumentException("rokTarget must be provided when embedding authority proofs");
                using var cntEnc = key.MapData(rokTarget, rokLockBytes, cntBuf, 0);
                ret.Write(cntEnc);
                // debug: raw encoded count bytes
                // (do not print raw encrypted bytes)

                // Debug: print embedded proof count and each proof (base64) for audit
                //Console.WriteLine($"[EncryptWithAuthority] embedding proofCount={proofCount}");

                for (int i = 0; i < proofCount; i++)
                {
                    var p = authorityProofs[i];
                    if (p == null) throw new ArgumentNullException(nameof(authorityProofs));
                    if (p.Length != proofPlainSize) throw new ArgumentException("authority proof size mismatch");
                    using var pEnc = key.MapData(rokTarget, rokLockBytes, p, 0);
                    ret.Write(pEnc);
                    //Console.WriteLine($"[EncryptWithAuthority] proof[{i}] embedded (base64 shown)");
                }
            }

            // 4) choose and write IV length + IV
            var ivLen = (byte)RandomNumberGenerator.GetInt32(7, 64);
            ret.Write(ivLen);
            var iv = RandomNumberGenerator.GetBytes(ivLen);
            using var headerEnc = key.MapData(iv, ivLen);
            ret.Write(headerEnc);

            // 5) encrypt the payload
            using var cipher = key.MapData(data, startLocation, iv);

            // 6) append a simple Blake3-based auth tag (32 bytes)
            {
                var b3 = Blake3.Hasher.New();
                b3.Update(cipher.AsReadOnlySpan);
                b3.Update(iv);
                Span<byte> auth = stackalloc byte[32];
                b3.Finalize(auth);
                using var authEnc = key.MapData(auth, ivLen, iv);
                ret.Write(authEnc);
            }

            // 7) finally, append the ciphertext bytes
            ret.Write(cipher);

            ret.Position = 0;
            return ret;
        }


        public static BufferStream Decrypt(BufferStream ciphertext, REKey key)
        {
            var startLocation = (short)ciphertext.Read7BitInt();
            // rokLock is thrown away when doing symmetric encryption
            var rokLock = ciphertext.ReadBytes(4);

            var ivLen = ciphertext.ReadByte();

            var iv = key.UnmapData(ciphertext, ivLen, default, ivLen);

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

        /// <summary>
        /// Verify authority proofs embedded in the ciphertext using the provided VRF verifier.
        /// This method expects fixed-size plaintext proofs to be stored directly after the
        /// 4-byte rokLock in the ciphertext, each proof encrypted using the same RedX
        /// control-stream encoding as other header fields.
        ///
        /// This function performs post-decryption verification: it replays RedX-core to
        /// compute the transcript Ti for each chunk and verifies the decrypted proof blob
        /// with the system-supplied IVrfVerifier. If any chunk fails verification, false
        /// is returned.
        ///
        /// Note: the ciphertext is not modified; the caller must ensure the ciphertext
        /// position is set appropriately before calling.
        /// </summary>
        public static bool VerifyAuthority(BufferStream ciphertext, REReadOnlyKey rok, ReadOnlySpan<byte> vrfPublicKey, IVrfVerifier verifier, int proofPlainSize = DefaultProofPlainSize, int chunkSize = DefaultAuthorityChunkSize)
        {
            if (verifier == null) throw new ArgumentNullException(nameof(verifier));

            // duplicate stream so we don't disturb caller's position
            var bs = new BufferStream(ciphertext.ToArray());
            bs.Position = 0;

            var header = ParseReadOnlyHeader(bs, rok, proofPlainSize);
            if (header == null)
                return false;

            var startLocation = header.StartLocation;
            var rokLock = header.RokLock;
            var proofs = header.Proofs;
            var iv = header.Iv;
            var authEnc = header.AuthEnc;

            // prepare a JumpGenerator for replaying walk outputs
            var bx = new JumpGenerator(rok.keyHash.Span, 1, iv.AsSpan());

            int chunkIndex = 0;
            while (bs.Position < bs.Length)
            {
                int remaining = (int)(bs.Length - bs.Position);
                int take = Math.Min(chunkSize, remaining);
                ReadOnlySpan<byte> chunkSpan = bs.ReadonlySliceAtCurrent(take);

                var hasher = Blake3.Hasher.New();
                hasher.Update(VrfDomainBytes);
                // pack startLocation (int32), ivLen (byte), chunkIndex (int32)
                Span<byte> tmp = stackalloc byte[9];
                int sLoc = startLocation;
                MemoryMarshal.Write(tmp.Slice(0, 4), ref sLoc);
                tmp[4] = (byte)iv.Length;
                int ci = chunkIndex;
                MemoryMarshal.Write(tmp.Slice(5, 4), ref ci);
                hasher.Update(tmp);
                hasher.Update(iv.AsSpan());
                hasher.Update(chunkSpan);

                // include RedX walk outputs consumed for this chunk
                for (int j = 0; j < chunkSpan.Length; j++)
                {
                    ushort skip = bx.NextJump16();
                    Span<byte> s2 = stackalloc byte[2];
                    MemoryMarshal.Write(s2, ref skip);
                    hasher.Update(s2);
                }

                Span<byte> Ti = stackalloc byte[32];
                hasher.Finalize(Ti);

                if (chunkIndex >= proofs.Count)
                    return false; // missing proof

                var proof = proofs[chunkIndex];
                if (!verifier.Verify(vrfPublicKey, Ti, proof))
                    return false;

                bs.Seek(take, SeekOrigin.Current);
                chunkIndex++;
            }

            // all chunks verified
            return true;
        }

        public static BufferStream Decrypt(BufferStream ciphertext, REReadOnlyKey key)
        {
            // Use unified header parser so Decrypt and VerifyAuthority consume the same bytes
            var header = ParseReadOnlyHeader(ciphertext, key, DefaultProofPlainSize);
            if (header == null)
                return null;

            var startLocation = header.StartLocation;
            var rokLock = header.RokLock;
            var iv = header.Iv;

            var plain = key.UnmapData(ciphertext, startLocation, header.RokLock.AsSpan(), iv.AsSpan());
            // NOTE: Authority verification is required when decrypting with a ROK.
            // The ciphertext must contain per-chunk encrypted authority proofs in the
            // control stream. Because authority metadata is RedX-encrypted, we
            // first replay RedX-core over the ciphertext bytes to compute per-chunk
            // transcripts Ti and then decrypt the corresponding encrypted proof
            // blocks and verify them using a supplied IVrfVerifier (system-level).
            //
            // For now, we do not perform verification here because the verifier
            // is system-level. Return the plaintext but signal to caller that
            // VerifyAuthority must be called before accepting the data.

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
        internal readonly Memory<ushort> nonces;         // ← NEW: one nonce per flat index
        private readonly Dictionary<uint, byte> chMap;
        // chPublicParam removed: chameleon-hash was removed from the ROK design

        // ctor: build a read-only key from a full REKey
        // NOTE: this no longer uses a chameleon-hash. Instead a Blake3-derived 32-bit
        // index/nonces digest is used to build the lookup table. This preserves the
        // ROK behavior while removing the chameleon dependency.
        public REReadOnlyKey(REKey key)
        {
            keyLength = key.keyLength;
            keyBlockSize = key.keyBlockSize;

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

                    // 3b) compute a 32-bit Blake3-derived digest (index || nonce)
                    h32 = RE.ComputeH32(keyHash.Span, i, r);
                }
                while (chMap.ContainsKey(h32));

                nonces.Span[i] = r;
                chMap[h32] = key.key[i];
            }

            // 4) no chameleon public params in this design
        }

        // ——————————————————————————————————————————————
        // decryption
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapData(BufferStream mapped, short startLocation, ReadOnlySpan<byte> rokLock, ReadOnlySpan<byte> iv = default, int count = -1)
        {
            // keyLength is keyBlockSize * 256
            startLocation = (short)(startLocation % this.keyLength);
            int curRow = startLocation / 256;
            int curCol = startLocation % 256;
            int ivLen = iv.Length;
            int blockSz = keyBlockSize;

            var output = new BufferStream();
            var bx = new JumpGenerator(keyHash.Span, 1, iv);
            var noncesSpan = nonces.Span;           // masked nonces from ROK
            var map = chMap;
            Span<byte> hashBuf = stackalloc byte[4];
            var streamLength = mapped.Length;
            var streamPos = mapped.Position;

            // If a nonce map header was written (dictionary, RLE), or a compact
            // marker, decode it when the caller provided an explicit count. The
            // MapData(rok, ...) encoding writes either a compact marker+payload
            // or a dictionary/RLE header. We only attempt to decode when count>0.
            ushort[] perPositionNonces = null;
            if (count > 0)
            {
                // peek marker
                int marker = mapped.ReadByte();
                if (marker >= 0)
                {
                    const byte CompactMarker = 0xFE;
                    if (marker == CompactMarker)
                    {
                        // compact mode: remaining "count" bytes are the XOR'd payload
                        var buf = new byte[count];
                        for (int i = 0; i < count; i++) buf[i] = (byte)mapped.ReadByte();
                        // derive keystream and unmask into a BufferStream to return
                        var ks = new byte[count];
                        using (var xof = new Blake3XofReader(keyHash.Span, rokLock))
                        {
                            xof.ReadNext(ks);
                        }
                        var outBuf = new byte[count];
                        for (int i = 0; i < count; i++) outBuf[i] = (byte)(buf[i] ^ ks[i]);
                        return new BufferStream(outBuf);
                    }
                    if (marker == 0x01)
                    {
                        int uniqueCount = mapped.ReadByte();
                        var unique = new ushort[uniqueCount];
                        for (int u = 0; u < uniqueCount; u++)
                            unique[u] = mapped.ReadUInt16();

                        perPositionNonces = new ushort[count];
                        for (int i = 0; i < count; i++)
                        {
                            int idx = mapped.ReadByte();
                            perPositionNonces[i] = unique[idx];
                        }
                    }
                    else if (marker == 0x00)
                    {
                        perPositionNonces = new ushort[count];
                        int p = 0;
                        while (p < count)
                        {
                            int hdr = mapped.ReadByte();
                            bool isRepeat = (hdr & 0x80) != 0;
                            int len = hdr & 0x7F;
                            if (isRepeat)
                            {
                                ushort val = mapped.ReadUInt16();
                                for (int k = 0; k < len; k++) perPositionNonces[p++] = val;
                            }
                            else
                            {
                                for (int k = 0; k < len; k++) perPositionNonces[p++] = mapped.ReadUInt16();
                            }
                        }
                    }
                    else
                    {
                        // not a header: rewind one byte and treat as no header
                        mapped.Position -= 1;
                    }
                }
                streamLength = mapped.Length;
                streamPos = mapped.Position;
            }

            for (int i = 0; (count < 0 || i < count) && streamPos < streamLength; i++)
            {
                int dist = mapped.ReadByte();
                if (dist < 0) break;
                streamPos++;

                // replay skip
                ushort skip = bx.NextJump16();
                int colJ = skip & 0xFF;
                int rowJ = (skip >> 8) % blockSz;

                curRow = (curRow + rowJ) % blockSz;
                curCol = (curCol + colJ) & 0xFF;

                // recover index
                int newCol = (curCol + dist) & 0xFF;
                int flatIndex = curRow * 256 + newCol;
                if ((uint)flatIndex >= (uint)noncesSpan.Length)
                    throw new CryptographicException($"ROK flatIndex out of range: {flatIndex}");

                // determine nonce: prefer per-position nonce from the encoded header
                // (if present), otherwise fallback to the ROK's stored nonce for the flat index
                ushort r = perPositionNonces != null && i < perPositionNonces.Length ? perPositionNonces[i] : noncesSpan[flatIndex];

                // compute Blake3-derived lookup value to recover plaintext
                uint h32 = RE.ComputeH32(keyHash.Span, flatIndex, r);

                if (!map.TryGetValue(h32, out byte plain))
                    throw new CryptographicException($"ROK lookup failed at index {flatIndex}");

                // undo IV
                if (ivLen > 0)
                    plain = (byte)((256 + plain - i - iv[i % ivLen]) % 256);

                output.WriteByte(plain);

                // advance cursor
                curCol = newCol;
                curRow = (curRow + 1) % blockSz;
            }

            output.Position = 0;
            return output;
        }



        /// <summary>
        /// Returns the key as a persistable byte array with the following format:
        /// [keyHashLength:int32][keyHash: byte[keyHashLength]][nonces: ushort[keyLen]][chMapKeys: uint[keyLen]]
        /// </summary>
        /// <returns></returns>
        public byte[] ToBytes()
        {
            int hashLen = keyHash.Length;           // e.g. 64
            int entryCount = keyLength;                // nonces + h32 pairs
            int total = 4                           // hashLen int
                      + hashLen
                      + entryCount * (2 + 4);      // ushort + uint per entry

            var blob = new byte[total];
            int off = 0;

            // 1) keyHashLength (int)
            MemoryMarshal.Write(blob.AsSpan(off, 4), ref hashLen);
            off += 4;

            // 2) keyHash bytes
            keyHash.Span.CopyTo(blob.AsSpan(off, hashLen));
            off += hashLen;

            // 3) (no public param)

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

            // 3) remaining bytes = entryCount*(2+4)
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
            // no chameleon in this design; keep chPublicParam reserved for compatibility
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
            // create a read-only key without chameleon-hash dependency
            return new REReadOnlyKey(this);
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


            var bx = new JumpGenerator(keyHash.Span, 1, iv);


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


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream MapData(REReadOnlyKey rok, ReadOnlySpan<byte> rokLock, ReadOnlySpan<byte> data, short startLocation, Span<byte> iv = default)
        {
            // normalize startLocation
            startLocation = (short)(startLocation % keyLength);
            int curRow = (startLocation / 256) % keyBlockSize;
            int curCol = (startLocation % 256);
            int ivLen = iv.Length;

            // Compact encoding threshold: if payload is small we use a compact
            // ROK-encoded mode to avoid the nonce-dictionary overhead.
            const int CompactThreshold = 128; // bytes
            const byte CompactMarker = 0xFE;

            // Small-blob fast path: write marker + XOR-keystream of payload derived
            // from (rok.keyHash || rokLock). This keeps the proof plaintext encrypted
            // under ROK without building large nonce tables.
            if (data.Length > 0 && data.Length <= CompactThreshold)
            {
                var outBs = new BufferStream();
                outBs.WriteByte(CompactMarker);
                // Derive keystream via Blake3 XOF(master=rok.keyHash, context=rokLock)
                var keystream = new byte[data.Length];
                using (var xof = new Blake3XofReader(rok.keyHash.Span, rokLock))
                {
                    xof.ReadNext(keystream);
                }
                Span<byte> enc = stackalloc byte[0]; // placeholder to avoid analyzer warnings
                var tmp = new byte[data.Length];
                for (int i = 0; i < data.Length; i++) tmp[i] = (byte)(data[i] ^ keystream[i]);
                outBs.WriteBytes(tmp);
                outBs.Position = 0;
                return outBs;
            }

            // 1) core encrypt: build distance‐stream + noncesOut[] + unique‐nonce map
            var cipher = new BufferStream();
            ushort[] noncesOut = new ushort[data.Length];

            // track unique nonces and assign each a small byte‐index
            var uniqMap = new Dictionary<ushort, byte>(capacity: 16);
            byte nextIdx = 0;

            var bx = new JumpGenerator(rok.keyHash.Span, 1, iv);
            var rokXof = new JumpGenerator(rokLock, 1);

            for (int i = 0; i < data.Length; i++)
            {
                // IV‐mix
                byte cur = data[i];
                if (ivLen > 0) cur = (byte)((cur + i + iv[i % ivLen]) & 0xFF);

                // jump
                ushort skip = bx.NextJump16();
                int colJump = skip & 0xFF;
                int rowJump = (skip >> 8) % keyBlockSize;
                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) & 0xFF;

                // map plaintext→column
                int newCol = rkd[curRow][cur];
                int dist = newCol - curCol; if (dist < 0) dist += 256;
                cipher.WriteByte((byte)dist);

                // record nonce
                int flatIdx = curRow * 256 + newCol;
                ushort thisNonce = rok.nonces.Span[flatIdx];
                noncesOut[i] = thisNonce;

                // track unique
                if (!uniqMap.ContainsKey(thisNonce))
                    uniqMap[thisNonce] = nextIdx++;

                // advance
                curCol = newCol;
                curRow = (curRow + 1) % keyBlockSize;
            }
            cipher.Position = 0;

            // 2) compute candidate sizes

            // A) dictionary‐encode size
            int uniqueCount = uniqMap.Count;           // ≤ 256
            int dictSize = 1       // marker
                             + 1      // count byte
                             + uniqueCount * 2  // each unique nonce as ushort
                             + data.Length      // 1 byte per nonce reference
                             ;

            // B) RLE‐encode size (just count, don’t build)
            int rleSize = 1; // marker
            int idx = 0;
            while (idx < noncesOut.Length)
            {
                // check for repeat
                int j = idx + 1;
                while (j < noncesOut.Length
                       && noncesOut[j] == noncesOut[idx]
                       && j - idx < 127) j++;
                int runLen = j - idx;
                if (runLen >= 2)
                {
                    rleSize += 1 + 2;  // hdr + one ushort
                    idx += runLen;
                }
                else
                {
                    // literal run
                    int litStart = idx;
                    j = idx + 1;
                    while (j < noncesOut.Length
                           && (j + 1 >= noncesOut.Length || noncesOut[j] != noncesOut[j + 1])
                           && j - litStart < 127) j++;
                    int litLen = j - litStart;
                    rleSize += 1 + litLen * 2;
                    idx += litLen;
                }
            }

            // 3) pick the winner and actually encode
            var ret = new BufferStream();
            if (dictSize <= rleSize)
            {
                // marker for dict
                ret.WriteByte(0x01);
                // count
                ret.WriteByte((byte)uniqueCount);
                // dump unique table
                foreach (var kv in uniqMap)
                    ret.Write(kv.Key);
                // dump each nonce as index
                for (int i = 0; i < noncesOut.Length; i++)
                    ret.WriteByte(uniqMap[noncesOut[i]]);
            }
            else
            {
                // marker for RLE
                ret.WriteByte(0x00);
                // real RLE encode
                int p = 0;
                while (p < noncesOut.Length)
                {
                    int q = p + 1;
                    while (q < noncesOut.Length
                           && noncesOut[q] == noncesOut[p]
                           && q - p < 127) q++;
                    int run = q - p;
                    if (run >= 2)
                    {
                        ret.WriteByte((byte)(0x80 | run));
                        ret.Write(noncesOut[p]);
                        p += run;
                    }
                    else
                    {
                        int litStart = p;
                        q = p + 1;
                        while (q < noncesOut.Length
                               && (q + 1 >= noncesOut.Length || noncesOut[q] != noncesOut[q + 1])
                               && q - litStart < 127) q++;
                        int lit = q - litStart;
                        ret.WriteByte((byte)lit);
                        for (int k = litStart; k < litStart + lit; k++)
                            ret.Write(noncesOut[k]);
                        p += lit;
                    }
                }
            }

            // 4) append distance cipher
            ret.Write(cipher);
            ret.Position = 0;
            return ret;
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

            var bx = new JumpGenerator(keyHash.Span, 1, iv);

            ushort randSkipArrayOfOne = 0;

            for (int i = 0; (count < 0 || i < count) && mapped.Position < mapped.Length; i++)
            {
                int skipVal = mapped.ReadByte();
                if (skipVal < 0) break;

                randSkipArrayOfOne = bx.NextJump16();
                var rowJump = ((randSkipArrayOfOne % keyLength) / 256);
                var colJump = randSkipArrayOfOne % 256;

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

    static class RLE
    {
        /// <summary>
        /// Run-length encodes an array of ushorts into a BufferStream:
        /// [hdr][data…][hdr][data…]…
        /// hdr<0x80 = literal run (length = hdr, up to 127 ushorts)
        /// hdr>=0x80 = repeat run (length = hdr&0x7F, then one ushort to repeat)
        /// </summary>
        public static BufferStream EncodeUShortRuns(ReadOnlySpan<ushort> data)
        {
            var bs = new BufferStream();
            int i = 0, N = data.Length;

            while (i < N)
            {
                // try a repeat run
                int j = i + 1;
                while (j < N && data[j] == data[i] && j - i < 127) j++;
                int runLen = j - i;
                if (runLen >= 2)
                {
                    bs.WriteByte((byte)(0x80 | runLen));
                    bs.Write(data[i]);
                    i += runLen;
                    continue;
                }

                // literal run (no two in a row)
                int litStart = i;
                j = i + 1;
                while (j < N && (j + 1 >= N || data[j] != data[j + 1]) && j - litStart < 127)
                    j++;
                int litLen = j - litStart + 1;

                bs.WriteByte((byte)litLen);
                for (int k = litStart; k < litStart + litLen; k++)
                    bs.Write(data[k]);

                i += litLen;
            }

            bs.Position = 0;
            return bs;
        }

        /// <summary>
        /// Decodes the above RLE back into an array of ushorts.
        /// </summary>
        public static ushort[] DecodeUShortRuns(BufferStream bs)
        {
            var list = new List<ushort>();
            while (bs.Position < bs.Length)
            {
                int hdr = bs.ReadByte();
                if (hdr < 0) break;
                bool isRepeat = (hdr & 0x80) != 0;
                int len = hdr & 0x7F;
                if (isRepeat)
                {
                    ushort val = (ushort)bs.ReadUInt16();
                    for (int i = 0; i < len; i++) list.Add(val);
                }
                else
                {
                    for (int i = 0; i < len; i++)
                        list.Add((ushort)bs.ReadUInt16());
                }
            }
            return list.ToArray();
        }

    }
}
