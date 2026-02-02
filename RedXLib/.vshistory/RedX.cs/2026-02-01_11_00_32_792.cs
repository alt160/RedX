using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Text;








namespace RedxLib
{
    /// <summary>
    /// The <see cref="RedX"/> class exposes the public surface for the RedX path-walking cipher.<br/>
    /// The cipher walks a keyed 2D permutation grid, uses an internal jump stream, and emits a key-row offset stream as ciphertext that is replayed to recover plaintext.<br/>
    /// RedX supports both symmetric encrypt/decrypt (full key) and a producer-locked<br/>
    /// Mint/Verify mode that enables decryption with a verifier key that is unable to produce ciphertext that itself is allowed to decrypt.<br/>
    /// This class concentrates entry points and domain-level constants to keep the algorithm auditable and frictionless to consume.<br/>
    /// <example>
    /// Symmetric encrypt/decrypt (full key):<br/>
    /// <code><![CDATA[
    /// var key = RedX.CreateKey();
    /// var plaintext = Encoding.UTF8.GetBytes("hello");
    /// var cipher = RedX.Encrypt(plaintext, key);
    /// var recovered = RedX.Decrypt(cipher, key);
    /// // recovered holds "hello"
    /// ]]></code>
    /// </example>
    /// <example>
    /// Mint/Verify with minting/verifier composites (no direct ECDsa handling):<br/>
    /// <code><![CDATA[
    /// var (minting, verifier) = RedX.CreateMintingKeyPair();
    /// var cipher = RedX.EncryptMint(data, minting);
    /// var recovered = RedX.DecryptMintWithAuthority(cipher, verifier);
    /// var mintingBlob = minting.ToBytes();
    /// var verifierBlob = verifier.ToBytes();
    /// var minting2 = RedX.CreateMintingKey(mintingBlob);
    /// var verifier2 = RedX.CreateVerifierKey(verifierBlob);
    /// ]]></code>
    /// </example>
    /// </summary>
    //====== TYPES ======
    public static class RedX
    {
        // ---------------------------------------------------------------------
        // Mint/Verify (origin-locked) authority mode
        // ---------------------------------------------------------------------
        // Domain separator for authority checkpoint signatures (byte[] to avoid span field restrictions)
        //Shared/Static Members
        internal static readonly byte[] AuthorityDomainBytes = "REDX_AUTH_CKPT_V1"u8.ToArray();
        /// <summary>
        /// Build the authority-signed message for a given checkpoint.<br/>
        /// Layout: domain separator || rKeyId32 || checkpointIndex (LE) || observerState32.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int BuildAuthorityMessage(ReadOnlySpan<byte> rKeyId32, int checkpointIndex, ReadOnlySpan<byte> observerState32, Span<byte> dest)
        {
            // message = domain || rKeyId32 || checkpointIndexLE || observerState32
            int domLen = AuthorityDomainBytes.Length;
            int need = domLen + 32 + 4 + ObserverStateSize;
            if (dest.Length < need) throw new ArgumentException("dest too small");

            AuthorityDomainBytes.AsSpan().CopyTo(dest);
            rKeyId32.CopyTo(dest.Slice(domLen, 32));
            BinaryPrimitives.WriteInt32LittleEndian(dest.Slice(domLen + 32, 4), checkpointIndex);
            observerState32.CopyTo(dest.Slice(domLen + 32 + 4, ObserverStateSize));
            return need;
        }
        // ---------------------------------------------------------------------
        // Mint/Verify (origin-locked) encryption using authority checkpoint signatures
        // ---------------------------------------------------------------------
        /// <summary>
        /// Choose a checkpoint cadence based on payload length and cap.<br/>
        /// Keeps small payloads dense (at least one checkpoint) and large payloads sparse while respecting maxCheckpoints.
        /// </summary>
        private static void ComputeCheckpointPlan(int totalSteps, int maxCheckpoints, out int checkpointCount, out int interval)
        {
            if (totalSteps <= 0)
            {
                checkpointCount = 0;
                interval = 0;
                return;
            }

            // Dense for small messages, sparser for large, capped.
            // ~1 checkpoint per 64 steps by default; interval forced >= 1.
            int desired = (totalSteps + 63) / 64;
            if (desired < 1) desired = 1;
            if (desired > maxCheckpoints) desired = maxCheckpoints;

            checkpointCount = desired;
            interval = (totalSteps + checkpointCount - 1) / checkpointCount; // ceil
            if (interval < 1) interval = 1;
        }
        /// <summary>
        /// Derive a 32-bit lookup token bound to the master key hash, a flat index, and a nonce.<br/>
        /// Both full keys and verifier keys rely on this token to map distances back to plaintext bytes.
        /// </summary>
        /// <param name="keyHash">First 64 bytes of the Blake3 hash of the master key.<br/>Only the first 8 bytes are consumed to keep the input small.</param>
        /// <param name="index">Flat index into the permutation grid (row*256 + col).<br/>Binds the token to the walk position.</param>
        /// <param name="nonce">Per-position nonce that blinds the mapping.<br/>Uniqueness is enforced when building verifier keys.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ComputeH32(ReadOnlySpan<byte> keyHash, int index, ushort nonce)
        {
            // Build a short buffer: keyHash slice || index || nonce → Blake3 → 32-bit token
            Span<byte> buf = stackalloc byte[8 + 4 + 2];
            for (int i = 0; i < 8; i++) buf[i] = keyHash[i];
            MemoryMarshal.Write(buf.Slice(8, 4), ref index);
            MemoryMarshal.Write(buf.Slice(12, 2), ref nonce);

            var h = Blake3.Hasher.New();
            h.Update(buf);
            Span<byte> out4 = stackalloc byte[4];
            h.Finalize(out4);
            return MemoryMarshal.Read<uint>(out4);
        }
        /// <summary>
        /// Create a full RedX key using a system provided random source seed.<br/>
        /// keySize controls the number of 256-byte rows in the permutation grid; the default (8) targets typical payload sizes.<br/>
        /// </summary>
        public static RedXKey CreateKey(byte keySize = 8)
        {
            return new RedXKey(keySize);
        }
        /// <summary>
        /// Create a deterministic RedX key using a caller-provided seed.<br/>
        /// keySize controls the number of 256-byte rows in the permutation grid; the default (8) targets typical payload sizes.<br/>
        /// </summary>
        public static RedXKey CreateKey(ReadOnlySpan<byte> seed, byte keySize = 8)
        {
            if (seed.Length < RedXKey.MinSeedLength)
                throw new ArgumentException($"Seed must be at least {RedXKey.MinSeedLength} bytes", nameof(seed));
            return new RedXKey(keySize, seed);
        }
        /// <summary>
        /// Rehydrate a full key from the serialized blob produced by RedXKey.ToBytes().<br/>
        /// Provides a frictionless entry point for callers that stay on the RedX static surface.<br/>
        /// </summary>
        public static RedXKey CreateKeyFromBytes(ReadOnlySpan<byte> serializedKey)
        {
            return RedXKey.FromBytes(serializedKey);
        }
        /// <summary>
        /// Rehydrate a minting key from its serialized blob.
        /// Use this when the minter needs to mint new ciphertexts or derive a verifier key.
        /// </summary>
        public static RedXMintingKey CreateMintingKey(ReadOnlySpan<byte> mintingKey)
        {
            return RedXMintingKey.FromBytes(mintingKey);
        }
        /// <summary>
        /// Create a minting/verifier key pair.
        /// Generates a fresh P-256 authority key (compact 64-byte P1363 signatures; widely supported) to sign checkpoints.
        /// Returns both minting and verifier composites so callers can hand off the verifier to consumers.
        /// </summary>
        public static (RedXMintingKey minting, RedXVerifierKey verifier) CreateMintingKeyPair()
        {
            var fullKey = CreateKey();
            var verifyingKey = fullKey.CreateVerifyingDecryptionKey();
            using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256); // P-256: interoperable, hardware-accelerated, compact signatures
            var authPriv = authority.ExportPkcs8PrivateKey();
            var authPub = authority.ExportSubjectPublicKeyInfo();

            var minting = new RedXMintingKey(fullKey, authPriv, authPub);
            var verifier = new RedXVerifierKey(verifyingKey, authPub);
            return (minting, verifier);
        }
        /// <summary>
        /// Rehydrate a minting/verifier pair from serialized blobs produced by CreateMintingKeyPair().<br/>
        /// Validates that the authority public key in both blobs matches to prevent mismatched inputs.
        /// </summary>
        public static (RedXMintingKey minting, RedXVerifierKey verifier) CreateMintingKeyPair(ReadOnlySpan<byte> mintingKey, ReadOnlySpan<byte> verifierKey)
        {
            var m = CreateMintingKey(mintingKey);
            var v = CreateVerifierKey(verifierKey);
            if (!m.AuthorityPublicKeySpki.AsSpan().SequenceEqual(v.AuthorityPublicKeySpki))
                throw new InvalidOperationException("Minting/verifier authority mismatch.");
            return (m, v);
        }
        /// <summary>
        /// Rehydrate a verifier key from its serialized blob.
        /// Use this on the consumer side to decrypt/verify authority checkpoints without holding the minting material.
        /// </summary>
        public static RedXVerifierKey CreateVerifierKey(ReadOnlySpan<byte> verifierKey)
        {
            return RedXVerifierKey.FromBytes(verifierKey);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void DebugMint(string message)
        {
            if (DebugMintVerify)
                Console.WriteLine("[mint-debug] " + message);
        }
        /// <summary>
        /// Symmetric decrypt using the full key.<br/>
        /// Assumes the symmetric wire layout: enc(startLocation1Bit) | enc(intCatLen) | enc(intCat) | key-row offset stream | [enc(integritySeal, optional)].<br/>
        /// When requireIntegrity is true, a 32-byte integrity seal must be present and valid; when false, no integrity seal is expected. Missing/invalid integrity fails decryption (no fallback).<br/>
        /// </summary>
        public static BufferStream Decrypt(BufferStream ciphertext, RedXKey key, bool requireIntegrity = true)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (key == null) throw new ArgumentNullException(nameof(key));

            if (!TryReadStartLocation1Bit(key, ciphertext, default, out ushort startLocationU16)) return null;
            var startLocation = unchecked((short)startLocationU16);
            using var intCatLenPlain = key.UnmapData(ciphertext, 0, default, 1);
            if (intCatLenPlain == null || intCatLenPlain.Length != 1) return null;
            var intCatLen = intCatLenPlain.AsReadOnlySpan[0];

            var intCat = key.UnmapData(ciphertext, intCatLen, default, intCatLen);
            if (intCat == null || intCat.Length != intCatLen) return null;

            int remaining = (int)(ciphertext.Length - ciphertext.Position);
            int integrityLen = requireIntegrity ? 32 : 0;
            if (remaining < integrityLen) return null;
            int rowOffsetLen = remaining - integrityLen;

            var rowOffsetBytes = ciphertext.ReadBytes(rowOffsetLen);
            byte[] integrityBytes = requireIntegrity ? ciphertext.ReadBytes(integrityLen) : Array.Empty<byte>();

            if (requireIntegrity)
            {
                if (integrityBytes.Length != 32) return null;
                var b3 = Blake3.Hasher.New();
                b3.Update(rowOffsetBytes);
                b3.Update(intCat.AsReadOnlySpan);
                Span<byte> integrity2 = stackalloc byte[32];
                b3.Finalize(integrity2);
                using var integrityPlain = key.UnmapData(new BufferStream(integrityBytes), intCatLen, intCat.AsReadOnlySpan, 32);
                if (integrityPlain == null || !integrityPlain.AsReadOnlySpan.SequenceEqual(integrity2))
                    return null;
            }

            var plain = key.UnmapData(new BufferStream(rowOffsetBytes), startLocation, intCat.AsReadOnlySpan);
            plain.Position = 0;
            return plain;
        }
        /// <summary>
        /// Overload for byte[] ciphertext convenience for symmetric decrypt.
        /// Wraps the byte array in a BufferStream and forwards to the symmetric decrypt path.
        /// </summary>
        public static BufferStream Decrypt(byte[] ciphertext, RedXKey key, bool requireIntegrity = true)
        {
            return Decrypt(new BufferStream(ciphertext), key, requireIntegrity);
        }
        /// <summary>
        /// Symmetric encrypt using only the full key.<br/>
        /// Wire layout: enc(startLocation1Bit) | enc(intCatLen) | enc(intCat) | key-row offset stream | [enc(integritySeal, optional when useIntegrity=true)].<br/>
        /// Integrity seal is computed over key-row offset stream||intCat; when useIntegrity is false the seal is omitted entirely.<br/>
        /// </summary>
        public static BufferStream Encrypt(byte[] data, RedXKey key, bool useIntegrity = true)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));

            var ret = new BufferStream();

            // 1) start location for payload walk (1-bit encoded)
            ushort startLocation = (ushort)RandomNumberGenerator.GetInt32(0, Math.Min(key.key.Length, ushort.MaxValue + 1));
            short startLocationShort = unchecked((short)startLocation);
            var startBuf = startLocation.To1BitEncodedBytes(randomizeUnusedBits: true);
            using (var startEnc = key.MapData(startBuf, 0))
                ret.Write(startEnc);

            // 2) interference catalyst header (len + encrypted catalyst)
            var intCatLen = (byte)RandomNumberGenerator.GetInt32(7, 64);
            var intCat = RandomNumberGenerator.GetBytes(intCatLen);
            Span<byte> intCatLenBuf = stackalloc byte[1];
            intCatLenBuf[0] = intCatLen;
            using (var intCatLenEnc = key.MapData(intCatLenBuf, 0))
                ret.Write(intCatLenEnc);
            using (var intCatEnc = key.MapData(intCat, intCatLen))
                ret.Write(intCatEnc);

            // 3) key-row offset stream
            byte[] rowOffsetBytes;
            using (var cipher = key.MapData(data, startLocationShort, intCat))
                rowOffsetBytes = cipher.AsReadOnlySpan.ToArray();
            ret.Write(rowOffsetBytes);

            // 4) optional integrity seal at end
            if (useIntegrity)
            {
                Span<byte> integritySeal = stackalloc byte[32];
                var b3 = Blake3.Hasher.New();
                b3.Update(rowOffsetBytes);
                b3.Update(intCat);
                b3.Finalize(integritySeal);
                using var integrityEnc = key.MapData(integritySeal, intCatLen, intCat);
                ret.Write(integrityEnc);
            }

            ret.Position = 0;
            return ret;
        }
        /// <summary>
        /// Mint (sign) using the minting key so ciphertext can be decrypted by a verifier key and verified via authority signatures.<br/>
        /// Checkpoints sample the key-row offset stream, accumulate observer state, and are signed with the authority's P-256 key to bind provenance.<br/>
        /// Use this when a verifier-holder must be able to decrypt while still requiring attestations from the authority key.
        /// </summary>
        /// <param name="vKeyTarget">Verifier key that will decrypt control-stream headers; null is allowed for full-key-only consumers.</param>
        /// <param name="authorityPrivateKeyPkcs8">Authority private key in PKCS#8 format used to sign checkpoints.</param>
        /// <param name="maxCheckpoints">Upper bound to defend against oversized metadata for large payloads.</param>
        internal static BufferStream Mint(byte[] data, RedXKey key, RedXVerifyingDecryptionKey vKeyTarget, ReadOnlySpan<byte> authorityPrivateKeyPkcs8, int maxCheckpoints = DefaultAuthorityCheckpointMax, bool useIntegrity = true)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (authorityPrivateKeyPkcs8.IsEmpty) throw new ArgumentException("authority private key is required", nameof(authorityPrivateKeyPkcs8));

            // output ciphertext buffer
            var ret = new BufferStream();

            // 1) random start location (payload walk, 1-bit encoded)
            ushort startLocation = (ushort)RandomNumberGenerator.GetInt32(0, Math.Min(key.key.Length, ushort.MaxValue + 1));
            short startLocationShort = unchecked((short)startLocation);

            // 2) per-message 4-byte lock to encrypt control stream
            var vKeyLockBytes = RandomNumberGenerator.GetBytes(4);
            ret.Write(vKeyLockBytes);

            // 3) encrypted start location (pos-0 mapping; verifier-key-bound when available)
            var startBuf = startLocation.To1BitEncodedBytes(randomizeUnusedBits: true);
            if (vKeyTarget != null)
            {
                using var startEnc = key.MapData(vKeyTarget, vKeyLockBytes, startBuf, 0);
                ret.Write(startEnc);
            }
            else
            {
                using var startEnc = key.MapData(startBuf, 0, vKeyLockBytes);
                ret.Write(startEnc);
            }

            // 4) interference catalyst (payload)
            var intCatLen = (byte)RandomNumberGenerator.GetInt32(7, 64);
            var intCat = RandomNumberGenerator.GetBytes(intCatLen);

            // Strategy: for small/medium payloads use a single accumulator signature; for larger payloads use checkpoints up to maxCheckpoints.
            const int SingleSigThreshold = 4 * 1024; // switch to checkpoints above this
            bool useCheckpoints = data.Length > SingleSigThreshold;

            int ckCount, interval;
            byte[] sigs;
            ReadOnlySpan<byte> rKeyId32 = key.keyHash.Span.Slice(0, 32);
            byte[] cipherBytes;
            byte[] intCatArr = intCat;

            if (useCheckpoints)
            {
                // checkpoint path
                ComputeCheckpointPlan(data.Length, maxCheckpoints, out ckCount, out interval);
                byte[] ckStates = ckCount > 0 ? new byte[ckCount * ObserverStateSize] : Array.Empty<byte>();
                using (var cipher = key.MapDataWithObserver(data, startLocationShort, intCatArr, interval, ckCount, ckStates))
                {
                    cipherBytes = cipher.AsReadOnlySpan.ToArray();
                }

                sigs = ckCount > 0 ? new byte[ckCount * DefaultAuthoritySigSize] : Array.Empty<byte>();
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportPkcs8PrivateKey(authorityPrivateKeyPkcs8, out _);

                    Span<byte> msg = stackalloc byte[AuthorityDomainBytes.Length + 32 + 4 + ObserverStateSize];

                    for (int i = 0; i < ckCount; i++)
                    {
                        var st = ckStates.AsSpan(i * ObserverStateSize, ObserverStateSize);
                        int msgLen = BuildAuthorityMessage(rKeyId32, i, st, msg);

                        var sigDest = sigs.AsSpan(i * DefaultAuthoritySigSize, DefaultAuthoritySigSize);
                        if (!ecdsa.TrySignData(msg.Slice(0, msgLen), sigDest, HashAlgorithmName.SHA256,
                                DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out int written) || written != DefaultAuthoritySigSize)
                            throw new CryptographicException("authority signing failed");
                    }
                }
                DebugMint($"Mint checkpoints: ckCount={ckCount} interval={interval} cipherLen={cipherBytes.Length} useIntegrity={useIntegrity}");
            }
            else
            {
                // single-accumulator path
                ckCount = 1;
                interval = data.Length; // force one snapshot at end

                byte[] ckStates = new byte[ObserverStateSize];
                using (var cipher = key.MapDataWithObserver(data, startLocationShort, intCatArr, interval, ckCount, ckStates))
                {
                    cipherBytes = cipher.AsReadOnlySpan.ToArray();
                }

                sigs = new byte[DefaultAuthoritySigSize];
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportPkcs8PrivateKey(authorityPrivateKeyPkcs8, out _);
                    Span<byte> msg = stackalloc byte[AuthorityDomainBytes.Length + 32 + 4 + ObserverStateSize];
                    int msgLen = BuildAuthorityMessage(rKeyId32, 0, ckStates, msg);
                    var sigDest = sigs.AsSpan();
                    if (!ecdsa.TrySignData(msg.Slice(0, msgLen), sigDest, HashAlgorithmName.SHA256,
                            DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out int written) || written != DefaultAuthoritySigSize)
                        throw new CryptographicException("authority signing failed");
                }
                DebugMint($"Mint single-accumulator: ckCount=1 interval={interval} cipherLen={cipherBytes.Length} useIntegrity={useIntegrity}");
            }

            // write encrypted checkpoint count and signatures (control stream encrypted under vKeyLockBytes at startLocation=0)
            // count is 4 bytes little-endian
            Span<byte> cntBuf = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(cntBuf, ckCount);

            if (vKeyTarget != null)
            {
                using var cntEnc = key.MapData(vKeyTarget, vKeyLockBytes, cntBuf, 0);
                ret.Write(cntEnc);
            }
            else
            {
                using var cntEnc = key.MapData(cntBuf, 0, vKeyLockBytes);
                ret.Write(cntEnc);
            }

            for (int i = 0; i < ckCount; i++)
            {
                var sig = sigs.AsSpan(i * DefaultAuthoritySigSize, DefaultAuthoritySigSize);
                if (vKeyTarget != null)
                {
                    using var sigEnc = key.MapData(vKeyTarget, vKeyLockBytes, sig, 0);
                    ret.Write(sigEnc);
                }
                else
                {
                    using var sigEnc = key.MapData(sig, 0, vKeyLockBytes);
                    ret.Write(sigEnc);
                }
            }

            // write interference catalyst length + catalyst (encrypted using header mapping)
            Span<byte> intCatLenBuf = stackalloc byte[1];
            intCatLenBuf[0] = intCatLen;
            if (vKeyTarget != null)
            {
                using var lenEnc = key.MapData(vKeyTarget, vKeyLockBytes, intCatLenBuf, 0);
                ret.Write(lenEnc);
                // Map the interference catalyst header without catalyst-mixing so verifying-key-side decrypt mirrors the symmetric path.
                using var headerEnc = key.MapData(vKeyTarget, vKeyLockBytes, intCat, intCatLen);
                ret.Write(headerEnc);
            }
            else
            {
                using var lenEnc = key.MapData(intCatLenBuf, 0, vKeyLockBytes);
                ret.Write(lenEnc);
                using var headerEnc = key.MapData(intCat, intCatLen);
                ret.Write(headerEnc);
            }

            // append ciphertext key-row offset stream
            ret.Write(cipherBytes);

            // optional integrity seal at end
            if (useIntegrity)
            {
                var b3 = Blake3.Hasher.New();
                b3.Update(cipherBytes);
                b3.Update(intCat);
                Span<byte> integritySeal = stackalloc byte[32];
                b3.Finalize(integritySeal);
                if (vKeyTarget != null)
                {
                    using var integrityEnc = key.MapData(vKeyTarget, vKeyLockBytes, integritySeal, intCatLen, intCat);
                    ret.Write(integrityEnc);
                }
                else
                {
                    using var integrityEnc = key.MapData(integritySeal, intCatLen, intCat);
                    ret.Write(integrityEnc);
                }
            }

            ret.Position = 0;
            return ret;
        }
        /// <summary>
        /// Mint (sign + produce ciphertext) using a full key and optional verifier-targeted header.
        /// </summary>
        public static BufferStream Mint(ReadOnlySpan<byte> data, RedXKey key, ReadOnlySpan<byte> authorityPrivateKeyPkcs8, int maxCheckpoints = DefaultAuthorityCheckpointMax, bool useIntegrity = true)
        {
            return Mint(data.ToArray(), key, null, authorityPrivateKeyPkcs8, maxCheckpoints, useIntegrity);
        }
        /// <summary>
        /// Mint using a minting key composite.
        /// Uses the minting key's full key for payload encryption, derives a verifier key for the header, and signs checkpoints with its authority private key.
        /// </summary>
        public static BufferStream Mint(ReadOnlySpan<byte> data, RedXMintingKey mintingKey, int maxCheckpoints = DefaultAuthorityCheckpointMax, bool useIntegrity = true)
        {
            if (mintingKey == null) throw new ArgumentNullException(nameof(mintingKey));
            var verifier = mintingKey.CreateVerifierKey();
            return Mint(data.ToArray(), mintingKey.FullKey, verifier.Key, mintingKey.AuthorityPrivateKeyPkcs8, maxCheckpoints, useIntegrity);
        }
        /// <summary>
        /// Read a 1-bit encoded start location from a full-key mapped header stream.<br/>
        /// Consumes mapped bytes from <paramref name="ciphertext"/> until the 1-bit varint terminates.<br/>
        /// Returns false on decode failure, unexpected EOF, or non-canonical encoding.<br/>
        /// </summary>
        /// <param name="key">Full key used to unmap the header bytes.<br/></param>
        /// <param name="ciphertext">Ciphertext stream positioned at the startLocation field.<br/></param>
        /// <param name="intCat">Header interference catalyst (vKeyLock for verifier headers, empty for symmetric).<br/></param>
        /// <param name="startLocation">Decoded start location value (ushort range).<br/></param>
        /// <returns>True on success; false on failure.<br/></returns>
        private static bool TryReadStartLocation1Bit(RedXKey key, BufferStream ciphertext, ReadOnlySpan<byte> intCat, out ushort startLocation)
        {
            startLocation = 0;
            if (key == null || ciphertext == null) return false;
            try
            {
                const int MaxBytes = 16; // ushort = 16 bits
                Span<byte> buf = stackalloc byte[MaxBytes];
                int idx = 0;
                bool terminated = false;

                int keyLength = key.keyLength;
                int keyBlockSize = key.keyBlockSize;
                int curRow = 0;
                int curCol = 0;
                int intCatLen = intCat.Length;

                var bx = new JumpGenerator(key.keyHash.Span, 1, intCat);

                for (; idx < MaxBytes; idx++)
                {
                    int skipVal = ciphertext.ReadByte();
                    if (skipVal < 0) return false;

                    ushort jump = bx.NextJump16();

                    int rowJump = (jump >> 8) % keyBlockSize;
                    int colJump = jump & 0xFF;

                    curRow = (curRow + rowJump) % keyBlockSize;
                    curCol = (curCol + colJump) % 256;

                    byte plain = key.key[curRow * 256 + (curCol + skipVal) % 256];
                    if (intCatLen > 0)
                        plain = (byte)((256 + plain - idx - intCat[idx % intCatLen]) % 256);

                    buf[idx] = plain;

                    curCol = (curCol + skipVal) % 256;
                    curRow = (curRow + 1) % keyBlockSize;

                    if ((plain & 0x80) == 0)
                    {
                        terminated = true;
                        idx++;
                        break;
                    }
                }

                if (!terminated || idx <= 0 || idx > MaxBytes) return false;

                ReadOnlySpan<byte> ro = buf.Slice(0, idx);
                startLocation = Integer1BitEncodingExtensions.Read1BitEncodedUInt16(ro, out int bytesRead);
                return bytesRead == idx;
            }
            catch
            {
                return false;
            }
        }
        /// <summary>
        /// Read a 1-bit encoded start location from a verifier-key compact header stream.<br/>
        /// Assumes the compact marker (0xFE) and XOR keystream encoding used by MapData(vKey, ...).<br/>
        /// Returns false on decode failure, unexpected EOF, or non-canonical encoding.<br/>
        /// </summary>
        /// <param name="vKey">Verifier key used to unmask the compact header.<br/></param>
        /// <param name="ciphertext">Ciphertext stream positioned at the startLocation field.<br/></param>
        /// <param name="vKeyLock">Verifier key lock bytes for keystream derivation.<br/></param>
        /// <param name="startLocation">Decoded start location value (ushort range).<br/></param>
        /// <returns>True on success; false on failure.<br/></returns>
        private static bool TryReadStartLocation1BitVKeyCompact(RedXVerifyingDecryptionKey verifyingKey, BufferStream ciphertext, ReadOnlySpan<byte> verifyingKeyLock, out ushort startLocation)
        {
            startLocation = 0;
            if (verifyingKey == null || ciphertext == null) return false;
            try
            {
                int marker = ciphertext.ReadByte();
                if (marker < 0 || marker != 0xFE) return false;

                const int MaxBytes = 16; // ushort = 16 bits
                Span<byte> buf = stackalloc byte[MaxBytes];
                Span<byte> ks = stackalloc byte[1];
                bool terminated = false;
                int idx = 0;

                using var xof = new Blake3XofReader(verifyingKey.keyHash.Span, verifyingKeyLock);

                for (; idx < MaxBytes; idx++)
                {
                    int enc = ciphertext.ReadByte();
                    if (enc < 0) return false;

                    xof.ReadNext(ks);
                    byte plain = (byte)(enc ^ ks[0]);
                    buf[idx] = plain;

                    if ((plain & 0x80) == 0)
                    {
                        terminated = true;
                        idx++;
                        break;
                    }
                }

                if (!terminated || idx <= 0 || idx > MaxBytes) return false;

                ReadOnlySpan<byte> ro = buf.Slice(0, idx);
                startLocation = Integer1BitEncodingExtensions.Read1BitEncodedUInt16(ro, out int bytesRead);
                return bytesRead == idx;
            }
            catch
            {
                return false;
            }
        }
        /// <summary>
        /// Verify + decrypt with mandatory authority verification (mint/verify).<br/>
        /// Wire layout (mint/verify): vKeyLock | enc(startLocation1Bit) | enc(ckCount) | enc(sigs…) | enc(intCatLen) | enc(intCat) | key-row offset stream | [enc(integritySeal, optional)].<br/>
        /// Integrity seal is computed over key-row offset stream||intCat; when requireIntegrity is true the seal must be present and valid; when false, no seal is expected. Missing/invalid integrity fails decryption (no fallback).<br/>
        /// Checkpoints/signatures are always required for provenance.<br/>
        /// </summary>
        internal static BufferStream VerifyAndDecrypt(BufferStream ciphertext, RedXVerifyingDecryptionKey verifyingKey, ReadOnlySpan<byte> authorityPublicKeySpki, int maxCheckpoints = DefaultAuthorityCheckpointMax, bool requireIntegrity = true)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (verifyingKey == null) throw new ArgumentNullException(nameof(verifyingKey));
            if (authorityPublicKeySpki.IsEmpty) throw new ArgumentException("authority public key is required", nameof(authorityPublicKeySpki));

            var verifyingKeyLock = ciphertext.ReadBytes(4);
            if (verifyingKeyLock.Length != 4) return null;

            if (!TryReadStartLocation1BitVKeyCompact(verifyingKey, ciphertext, verifyingKeyLock, out ushort startLocationU16))
            {
                DebugMint("VerifyAndDecrypt(vKey) startLocation decode failed");
                return null;
            }
            var startLocation = unchecked((short)startLocationU16);

            // read encrypted checkpoint count
            try
            {
                var cntPlain = verifyingKey.UnmapData(ciphertext, 0, verifyingKeyLock, default, 4);
                if (cntPlain == null || cntPlain.Length != 4)
                {
                    DebugMint("VerifyAndDecrypt(vKey) cntPlain null/len!=4");
                    return null;
                }
                int ckCount = BinaryPrimitives.ReadInt32LittleEndian(cntPlain.AsReadOnlySpan);
                if (ckCount < 0 || ckCount > maxCheckpoints)
                {
                    DebugMint($"VerifyAndDecrypt(vKey) ckCount out of range: {ckCount}");
                    return null;
                }

                // read encrypted signatures
                byte[] sigs = ckCount > 0 ? new byte[ckCount * DefaultAuthoritySigSize] : Array.Empty<byte>();
                for (int i = 0; i < ckCount; i++)
                {
                    var sigPlain = verifyingKey.UnmapData(ciphertext, 0, verifyingKeyLock, default, DefaultAuthoritySigSize);
                    if (sigPlain == null || sigPlain.Length != DefaultAuthoritySigSize)
                    {
                        DebugMint($"VerifyAndDecrypt(vKey) sig[{i}] null/len!=64");
                        return null;
                    }
                    sigPlain.AsReadOnlySpan.CopyTo(sigs.AsSpan(i * DefaultAuthoritySigSize, DefaultAuthoritySigSize));
                }

                // intCat header (reject compact)
                using var intCatLenPlain = verifyingKey.UnmapData(ciphertext, 0, verifyingKeyLock, default, 1);
                if (intCatLenPlain == null || intCatLenPlain.Length != 1) return null;
                var intCatLen = intCatLenPlain.AsReadOnlySpan[0];
                var intCat = verifyingKey.UnmapData(ciphertext, (short)intCatLen, verifyingKeyLock, default, intCatLen, rejectCompactHeader: false);
                if (intCat == null || intCat.Length != intCatLen)
                    throw new InvalidDataException("Interference catalyst header decode failed (verifier path).");

                int remaining = (int)(ciphertext.Length - ciphertext.Position);
                // Integrity seal is verifier-key mapped; compact encoding adds a 1-byte marker.
                int integrityEncodedLen = requireIntegrity ? 33 : 0; // MapData(vKey, ...) uses compact path for 32-byte integrity seal
                if (remaining < integrityEncodedLen) return null;
                int cipherLen = remaining - integrityEncodedLen;
                var rowOffsetBytes = ciphertext.ReadBytes(cipherLen);
                byte[] integrityEnc = requireIntegrity ? ciphertext.ReadBytes(integrityEncodedLen) : Array.Empty<byte>();

                if (requireIntegrity)
                {
                    if (integrityEnc.Length != integrityEncodedLen)
                    {
                        DebugMint($"VerifyAndDecrypt(vKey) integrityEnc length mismatch (got {integrityEnc.Length}, want {integrityEncodedLen})");
                        return null;
                    }
                    using var integrityPlain = verifyingKey.UnmapData(new BufferStream(integrityEnc), (short)intCatLen, verifyingKeyLock, intCat.AsReadOnlySpan, 32, rejectCompactHeader: false);
                    if (integrityPlain == null || integrityPlain.Length != 32)
                    {
                        DebugMint("VerifyAndDecrypt(vKey) integrityPlain null/len!=32");
                        return null;
                    }
                    var b3 = Blake3.Hasher.New();
                    b3.Update(rowOffsetBytes);
                    b3.Update(intCat.AsReadOnlySpan);
                    Span<byte> integrity2 = stackalloc byte[32];
                    b3.Finalize(integrity2);
                    if (!integrityPlain.AsReadOnlySpan.SequenceEqual(integrity2))
                    {
                        DebugMint("VerifyAndDecrypt(vKey) integrity seal mismatch");
                        return null;
                    }
                }

                // derive checkpoint plan based on jump length
                ComputeCheckpointPlan(cipherLen, maxCheckpoints, out int planCount, out int interval);
                if (ckCount == 1 && planCount != 1)
                {
                    // Encryption used single-accumulator path; force interval to full length
                    interval = cipherLen;
                }
                else if (planCount != ckCount)
                {
                    DebugMint($"VerifyAndDecrypt(vKey) plan mismatch planCount={planCount} ckCount={ckCount}");
                    return null;
                }
                DebugMint($"VerifyAndDecrypt(vKey) start={startLocationU16} ckCount={ckCount} interval={interval} cipherLen={cipherLen} intCatLen={intCatLen} requireIntegrity={requireIntegrity}");

                ReadOnlySpan<byte> rKeyId32 = verifyingKey.keyHash.Span.Slice(0, 32);

                // Pass 1: verify only (discard plaintext)
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportSubjectPublicKeyInfo(authorityPublicKeySpki, out _);
                    var verifyOnly = verifyingKey.UnmapDataWithAuthority(new BufferStream(rowOffsetBytes), startLocation, intCat.AsReadOnlySpan, interval, ckCount, sigs, ecdsa, rKeyId32, count: cipherLen);
                    if (verifyOnly == null)
                        return null;
                }

                using var ecdsa2 = ECDsa.Create();
                ecdsa2.ImportSubjectPublicKeyInfo(authorityPublicKeySpki, out _);
                var plain = verifyingKey.UnmapDataWithAuthority(new BufferStream(rowOffsetBytes), startLocation, intCat.AsReadOnlySpan, interval, ckCount, sigs, ecdsa2, rKeyId32, count: cipherLen);
                if (plain == null) return null;
                plain.Position = 0;
                return plain;
            }
            catch
            {
                return null;
            }
        }
        /// <summary>
        /// Convenience overload that uses a verifier composite for verify+decrypt.
        /// Returns null on any failure and never emits plaintext without successful verification.
        /// </summary>
        public static BufferStream VerifyAndDecrypt(BufferStream ciphertext, RedXVerifierKey verifierKey, int maxCheckpoints = DefaultAuthorityCheckpointMax, bool requireIntegrity = true)
        {
            if (verifierKey == null) throw new ArgumentNullException(nameof(verifierKey));
            return VerifyAndDecrypt(ciphertext, verifierKey.Key, verifierKey.AuthorityPublicKeySpki, maxCheckpoints, requireIntegrity);
        }








        // Lightweight toggle for temporary mint/verify tracing; set false to silence.
        //======  FIELDS  ======
        internal const bool DebugMintVerify = true;
        // Default cap on embedded checkpoint signatures (mint/verify mode)
        internal const int DefaultAuthorityCheckpointMax = 64;
        // Default fixed signature size for P-256 ECDSA in IEEE-P1363 fixed format.
        internal const int DefaultAuthoritySigSize = 64;
        internal const int ObserverStateSize = 32;
        // default chunk size (legacy VRF path) – retained for compatibility with older ciphertexts.
        private const int DefaultAuthorityChunkSize = 4096;
        // default fixed proof size (bytes) for legacy per-chunk proofs (VRF).
        private const int DefaultProofPlainSize = 96;
    }

    /// <summary>
    /// Full RedX key used for encryption and for deriving verifier keys.<br/>
    /// Holds the permutation rows, inverse lookup tables, and Blake3 key hash that seeds jump generators.<br/>
    /// Consumers encrypt with this type; verifier keys derived from it can decrypt without exposing the forward permutation.
    /// </summary>
    public class RedXKey
    {
        /// <summary>
        /// Rehydrate a key from the serialized blob produced by ToBytes().<br/>
        /// Validates the version, enforces keyLen divisibility by 256, and recomputes inverse rows and key hash.<br/>
        /// </summary>
        //Shared/Static Members
        public static RedXKey FromBytes(ReadOnlySpan<byte> blob)
        {
            if (blob.Length < 1 + 4) throw new ArgumentException("Key blob too small", nameof(blob));
            byte ver = blob[0];
            if (ver != KeyBlobVersion) throw new NotSupportedException($"Key blob version {ver} not supported");
            int keyLen = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(1, 4));
            if (keyLen <= 0) throw new InvalidOperationException("Invalid key length");
            if (blob.Length != 1 + 4 + keyLen) throw new InvalidOperationException("Key blob length mismatch");
            return RehydrateFromRawKeyBytes(blob.Slice(5, keyLen));
        }
        /// <summary>
        /// Rehydrate a key from a hex-encoded serialized blob (same layout as ToBytes()).<br/>
        /// Trims surrounding whitespace and validates the hex payload before reconstruction.<br/>
        /// </summary>
        public static RedXKey FromHex(string hex)
        {
            if (hex == null) throw new ArgumentNullException(nameof(hex));
            var trimmed = hex.Trim();
            var bytes = Convert.FromHexString(trimmed);
            return FromBytes(bytes);
        }
        /// <summary>
        /// Internal helper to rebuild a key from raw permutation bytes (length divisible by 256).<br/>
        /// Recomputes inverse rows and key hash to keep downstream operations deterministic.<br/>
        /// </summary>
        internal static RedXKey RehydrateFromRawKeyBytes(ReadOnlySpan<byte> keyBytes)
        {
            if (keyBytes.Length == 0 || (keyBytes.Length % 256) != 0)
                throw new ArgumentException("Key bytes length must be a positive multiple of 256", nameof(keyBytes));

            int blockSize = keyBytes.Length / 256;
            if (blockSize > byte.MaxValue)
                throw new InvalidOperationException("Key block size exceeds supported range");

            var key = new RedXKey((byte)blockSize)
            {
                key = keyBytes.ToArray(),
                keyLength = keyBytes.Length,
                keyBlockSize = (byte)blockSize,
                rkd = new byte[blockSize][]
            };

            for (int row = 0; row < blockSize; row++)
            {
                var inv = new byte[256];
                for (int col = 0; col < 256; col++)
                {
                    byte val = keyBytes[row * 256 + col];
                    inv[val] = (byte)col;
                }
                key.rkd[row] = inv;
            }

            var b3 = Blake3.Hasher.New();
            b3.Update(keyBytes);
            var kh = new byte[64];
            b3.Finalize(kh);
            key.keyHash = new Memory<byte>(kh);

            return key;
        }
        /// <summary>
        /// Performs a Fisher-Yates shuffle on a Memory<byte>.<br/>
        /// Uses a cryptographically secure RNG when no Random is supplied.
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
        /// Performs a Fisher-Yates shuffle on a Memory<byte>.<br/>
        /// Uses a cryptographically secure RNG when no Random is supplied.
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
        /// Performs a Fisher-Yates shuffle on a byte array.<br/>
        /// Uses a cryptographically secure RNG when no Random is supplied.
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








        //======  FIELDS  ======
        internal const int MinSeedLength = 16;
        private const byte KeyBlobVersion = 1;
        private static readonly byte[] KeySeedDomainBytes = "REDX_KEY_SEED_V1"u8.ToArray();








        internal byte[] key;
        internal byte keyBlockSize;
        internal Memory<byte> keyHash;
        internal int keyLength;
        internal byte[][] rkd;








        /// <summary>
        /// Create a full RedX key with the given row count (keySize).<br/>
        /// Each row is a Fisher-Yates shuffle of byte values, forming the keyed 2D permutation used by the walk and key-row offset stream.
        /// </summary>
        //======  CONSTRUCTORS  ======
        public RedXKey(byte keySize = 8)
        {
            InitializeKey(keySize, maxExclusive => RandomNumberGenerator.GetInt32(maxExclusive));
        }

        /// <summary>
        /// Create a deterministic RedX key using a caller-provided seed.<br/>
        /// The same seed and keySize will always produce the same key material.
        /// </summary>
        public RedXKey(byte keySize, ReadOnlySpan<byte> seed)
        {
            if (seed.Length < MinSeedLength)
                throw new ArgumentException($"Seed must be at least {MinSeedLength} bytes", nameof(seed));
            using var xof = new Blake3XofReader(seed, KeySeedDomainBytes);
            InitializeKey(keySize, maxExclusive => NextDeterministicInt(xof, maxExclusive));
        }

        private void InitializeKey(byte keySize, Func<int, int> nextInt)
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

                ShuffleDeterministic(array.AsSpan(), nextInt);

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

        private static void ShuffleDeterministic(Span<byte> span, Func<int, int> nextInt)
        {
            if (span.IsEmpty || span.Length <= 1)
                return;

            for (int i = span.Length - 1; i > 0; i--)
            {
                int j = nextInt(i + 1);
                byte temp = span[i];
                span[i] = span[j];
                span[j] = temp;
            }
        }

        private static int NextDeterministicInt(Blake3XofReader xof, int maxExclusive)
        {
            if (maxExclusive <= 0) throw new ArgumentOutOfRangeException(nameof(maxExclusive));

            Span<byte> buf = stackalloc byte[4];
            uint limit = uint.MaxValue - (uint.MaxValue % (uint)maxExclusive);
            uint value;
            do
            {
                xof.ReadNext(buf);
                value = MemoryMarshal.Read<uint>(buf);
            } while (value >= limit);

            return (int)(value % (uint)maxExclusive);
        }








        /// <summary>
        /// Derive a verifier key from this key.<br/>
        /// The derived key contains lookup tokens and nonces only; it cannot be used to encrypt or regenerate the permutation.
        /// </summary>
        //======  METHODS  ======
        internal RedXVerifyingDecryptionKey CreateVerifyingDecryptionKey()
        {
            // create an internal verifying decryption key from the full key
            return new RedXVerifyingDecryptionKey(this);
        }

        /// <summary>
        /// Map data for a specific verifier key target by encoding per-position nonces alongside the key-row offset stream.<br/>
        /// Small payloads use a compact XOR-with-XOF fast path; larger payloads choose between dictionary and RLE nonce encodings for efficiency.<br/>
        /// This keeps the control stream decryptable by the verifier key without leaking the full permutation.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal BufferStream MapData(RedXVerifyingDecryptionKey verifyingKey, ReadOnlySpan<byte> verifyingKeyLock, ReadOnlySpan<byte> data, short startLocation, Span<byte> intCat = default)
        {
            // normalize startLocation (treat as ushort for full range)
            int start = ((ushort)startLocation) % keyLength;
            int curRow = (start / 256) % keyBlockSize;
            int curCol = (start % 256);
            int intCatLen = intCat.Length;

            // Compact encoding threshold: if payload is small we use a compact
            // vKey-encoded mode to avoid the nonce-dictionary overhead.
            const int CompactThreshold = 128; // bytes
            const byte CompactMarker = 0xFE;

            // Small-blob fast path: write marker + XOR-keystream of payload derived
            // from (vKey.keyHash || vKeyLock). This keeps the proof plaintext encrypted
            // under the verifier key without building large nonce tables.
            if (data.Length > 0 && data.Length <= CompactThreshold)
            {
                var outBs = new BufferStream();
                outBs.WriteByte(CompactMarker);
                // Derive keystream via Blake3 XOF(master=verifyingKey.keyHash, context=verifyingKeyLock)
                var keystream = new byte[data.Length];
                using (var xof = new Blake3XofReader(verifyingKey.keyHash.Span, verifyingKeyLock))
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

            // 1) core encrypt: build key-row offset stream + noncesOut[] + unique-nonce map
            var cipher = new BufferStream();
            ushort[] noncesOut = new ushort[data.Length];

            // track unique nonces and assign each a small byte‐index
            var uniqMap = new Dictionary<ushort, byte>(capacity: 16);
            byte nextIdx = 0;

            var bx = new JumpGenerator(verifyingKey.keyHash.Span, 1, intCat);
            var vKeyXof = new JumpGenerator(verifyingKeyLock, 1);

            for (int i = 0; i < data.Length; i++)
            {
                // catalyst-mix
                byte cur = data[i];
                if (intCatLen > 0) cur = (byte)((cur + i + intCat[i % intCatLen]) & 0xFF);

                // jump
                ushort j = bx.NextJump16();
                int rowJump = (j >> 8) % keyBlockSize;
                int colJump = j & 0xFF;
                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) & 0xFF;

                // map plaintext→column
                int newCol = rkd[curRow][cur];
                int dist = newCol - curCol; if (dist < 0) dist += 256;
                cipher.WriteByte((byte)dist);

                // record nonce
                int flatIdx = curRow * 256 + newCol;
                ushort thisNonce = verifyingKey.nonces.Span[flatIdx];
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

            // 4) append key-row offset stream
            ret.Write(cipher);
            ret.Position = 0;
            return ret;
        }








        /// <summary>
        /// Map plaintext into a key-row offset stream using the full key.<br/>
        /// The walker uses an internal pseudo-random jump stream across rows/cols, then emits the forward distance to the plaintext byte in the new row.<br/>
        /// Interference catalyst mixing folds position and caller catalyst into the plaintext to resist replay.
        /// </summary>
        //------ Public Methods -----
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream MapData(ReadOnlySpan<byte> data, short startLocation, Span<byte> intCat = default)
        {
            // wrap startLocation (treat as ushort for full range)
            int start = ((ushort)startLocation) % keyLength;
            var sRow = (start / 256) % keyBlockSize;
            var sCol = start % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            var intCatLen = intCat.Length;


            var bx = new JumpGenerator(keyHash.Span, 1, intCat);


            ushort randSkipArrayOfOne = 0;
            byte curByte = 0;
            for (int i = 0; i < data.Length; i++)
            {
                curByte = data[i];
                if (intCatLen > 0)
                    curByte = (byte)((curByte + i + intCat[i % intCatLen]) % 256);

                // 🔁 Step 1: Random jump
                ushort j = bx.NextJump16();
                int rowJump = (j >> 8) % keyBlockSize;
                int colJump = j & 0xFF;

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

        /// <summary>
        /// Map plaintext while tracking observer state for authority checkpoints.<br/>
        /// Observer state mixes landing bytes, jump deltas, emitted distances, and step counter to give cryptographers a reproducible transcript.<br/>
        /// Checkpoints snapshot the observer state at fixed intervals and return it via <paramref name="checkpointStates32xN"/>.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream MapDataWithObserver(ReadOnlySpan<byte> data, short startLocation, ReadOnlySpan<byte> intCat, int checkpointInterval, int checkpointCount, Span<byte> checkpointStates32xN)
        {
            if (checkpointCount < 0) throw new ArgumentOutOfRangeException(nameof(checkpointCount));
            if (checkpointCount > 0)
            {
                if (checkpointInterval <= 0) throw new ArgumentOutOfRangeException(nameof(checkpointInterval));
                if (checkpointStates32xN.Length < checkpointCount * RedX.ObserverStateSize)
                    throw new ArgumentException("checkpointStates32xN too small", nameof(checkpointStates32xN));
            }

            // wrap startLocation (treat as ushort for full range)
            int start = ((ushort)startLocation) % keyLength;
            var sRow = (start / 256) % keyBlockSize;
            var sCol = start % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            int intCatLen = intCat.Length;

            var bx = new JumpGenerator(keyHash.Span, 1, intCat);

            Span<byte> obsState = stackalloc byte[RedX.ObserverStateSize];
            obsState.Clear();
            uint step = 0;

            int ckWrite = 0;

            for (int i = 0; i < data.Length; i++)
            {
                byte curByte = data[i];
                if (intCatLen > 0)
                    curByte = (byte)((curByte + i + intCat[i % intCatLen]) % 256);

                ushort jump = bx.NextJump16();
                int rowJump = (jump >> 8) % keyBlockSize;
                int colJump = jump & 0xFF;

                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) % 256;

                // landing byte (temporal internal state)
                byte landing = key[curRow * 256 + curCol];
                int mixIdx = (int)(step & 31);
                obsState[mixIdx] ^= landing;
                obsState[(mixIdx + 11) & 31] ^= (byte)jump;
                obsState[(mixIdx + 17) & 31] ^= (byte)(jump >> 8);
                obsState[(mixIdx + 23) & 31] ^= (byte)step;
                step++;

                // map plaintext to column
                int col = rkd[curRow][curByte];

                int dist = col - curCol;
                if (dist < 0) dist += 256;

                // bind authority observer state to ciphertext encoding (distance/new column)
                obsState[(mixIdx + 5) & 31] ^= (byte)dist;
                obsState[(mixIdx + 7) & 31] ^= (byte)col;

                output.WriteByte((byte)dist);

                curCol = col;
                curRow = (curRow + 1) % keyBlockSize;

                // snapshot observer state at checkpoints (after processing this step)
                if (checkpointCount > 0 && ((i + 1) % checkpointInterval) == 0 && ckWrite < checkpointCount)
                {
                    obsState.CopyTo(checkpointStates32xN.Slice(ckWrite * RedX.ObserverStateSize, RedX.ObserverStateSize));
                    ckWrite++;
                }
            }

            // ensure last checkpoint exists if checkpoints requested and none landed exactly on end
            if (checkpointCount > 0 && ckWrite < checkpointCount)
            {
                obsState.CopyTo(checkpointStates32xN.Slice(ckWrite * RedX.ObserverStateSize, RedX.ObserverStateSize));
            }

            output.Position = 0;
            return output;
        }

        /// <summary>
        /// Serialize the full key permutation for storage/transport.<br/>
        /// Layout: [ver:byte][keyLen:int32][keyBytes:keyLen], where keyLen must be divisible by 256.<br/>
        /// </summary>
        public byte[] ToBytes()
        {
            int keyLen = key.Length;
            var buf = new byte[1 + 4 + keyLen];
            buf[0] = KeyBlobVersion;
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(1, 4), keyLen);
            key.AsSpan().CopyTo(buf.AsSpan(5));
            return buf;
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
        /// Inverses the skip‐distance mapping performed by MapData.<br/>
        /// Replays the same jump generator (seeded by keyHash and interference catalyst) to land on the correct rows/cols and undo catalyst mixing.
        /// </summary>
        /// <param name="mapped">Stream returned by MapData (position = 0).</param>
        /// <param name="intCat">Same interference catalyst span passed into MapData.</param>
        /// <param name="count">
        /// If >0, stop after <paramref name="count"/> bytes (otherwise, until end-of-stream).
        /// </param>
        /// <returns>Recovered plaintext.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapData(BufferStream mapped, short startLocation, ReadOnlySpan<byte> intCat = default, int count = -1)
        {
            int start = ((ushort)startLocation) % (keyBlockSize * 256);
            var sRow = start / 256;
            var sCol = start % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            var intCatLen = intCat.Length;

            var bx = new JumpGenerator(keyHash.Span, 1, intCat);

            ushort randSkipArrayOfOne = 0;

            for (int i = 0; (count < 0 || i < count) && mapped.Position < mapped.Length; i++)
            {
                int skipVal = mapped.ReadByte();
                if (skipVal < 0) break;

                ushort j = bx.NextJump16();
                int rowJump = (j >> 8) % keyBlockSize;
                int colJump = j & 0xFF;

                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) % 256;

                byte plain = key[curRow * 256 + (curCol + skipVal) % 256];

                if (intCatLen > 0)
                    plain = (byte)((256 + plain - i - intCat[i % intCatLen]) % 256);

                curCol = (curCol + skipVal) % 256;
                curRow = (curRow + 1) % keyBlockSize;

                output.WriteByte(plain);
            }

            output.Position = 0;
            return output;
        }

        /// <summary>
        /// Convenience overload that accepts an in-memory key-row offset stream instead of BufferStream.<br/>
        /// Useful for tests or callers that already materialized the cipher bytes.
        /// </summary>
        public BufferStream UnmapData(Memory<byte> skipsSpan, short startLocation, ReadOnlySpan<byte> intCat = default, int count = -1)
        {
            return UnmapData(new BufferStream(skipsSpan), startLocation, intCat, count);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapDataWithAuthority(BufferStream mapped, short startLocation, ReadOnlySpan<byte> intCat, int checkpointInterval, int checkpointCount, ReadOnlySpan<byte> sigs64xN, ECDsa authorityPublicKey, ReadOnlySpan<byte> rKeyId32, int count = -1)
        {
            if (authorityPublicKey == null) throw new ArgumentNullException(nameof(authorityPublicKey));
            if (checkpointCount < 0) throw new ArgumentOutOfRangeException(nameof(checkpointCount));
            if (checkpointCount > 0)
            {
                if (checkpointInterval <= 0) throw new ArgumentOutOfRangeException(nameof(checkpointInterval));
                if (sigs64xN.Length < checkpointCount * RedX.DefaultAuthoritySigSize)
                    throw new ArgumentException("sigs64xN too small", nameof(sigs64xN));
                if (rKeyId32.Length != 32) throw new ArgumentException("rKeyId32 must be 32 bytes", nameof(rKeyId32));
            }

            int start = ((ushort)startLocation) % (keyBlockSize * 256);
            var sRow = start / 256;
            var sCol = start % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            int intCatLen = intCat.Length;

            var bx = new JumpGenerator(keyHash.Span, 1, intCat);

            Span<byte> obsState = stackalloc byte[RedX.ObserverStateSize];
            obsState.Clear();
            uint step = 0;
            int ckRead = 0;

            Span<byte> msg = stackalloc byte[RedX.AuthorityDomainBytes.Length + 32 + 4 + RedX.ObserverStateSize];

            for (int i = 0; (count < 0 || i < count) && mapped.Position < mapped.Length; i++)
            {
                int dist = mapped.ReadByte();
                if (dist < 0) break;

                ushort jump = bx.NextJump16();
                int rowJump = (jump >> 8) % keyBlockSize;
                int colJump = jump & 0xFF;

                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) % 256;

                // landing byte (temporal internal state)
                byte landing = key[curRow * 256 + curCol];
                int mixIdx = (int)(step & 31);
                obsState[mixIdx] ^= landing;
                obsState[(mixIdx + 11) & 31] ^= (byte)jump;
                obsState[(mixIdx + 17) & 31] ^= (byte)(jump >> 8);
                obsState[(mixIdx + 23) & 31] ^= (byte)step;
                step++;

                byte plain = key[curRow * 256 + (curCol + dist) % 256];
                // bind authority state to the distance encoding and resulting column
                obsState[(mixIdx + 5) & 31] ^= (byte)dist;
                obsState[(mixIdx + 7) & 31] ^= (byte)((curCol + dist) % 256);

                if (intCatLen > 0)
                    plain = (byte)((256 + plain - i - intCat[i % intCatLen]) % 256);

                curCol = (curCol + dist) % 256;
                curRow = (curRow + 1) % keyBlockSize;

                output.WriteByte(plain);

                if (checkpointCount > 0 && ((i + 1) % checkpointInterval) == 0 && ckRead < checkpointCount)
                {
                    int msgLen = RedX.BuildAuthorityMessage(rKeyId32, ckRead, obsState, msg);
                    var sig = sigs64xN.Slice(ckRead * RedX.DefaultAuthoritySigSize, RedX.DefaultAuthoritySigSize);
                    if (!authorityPublicKey.VerifyData(msg.Slice(0, msgLen), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    {
                        RedX.DebugMint("Full-key authority signature verify failed during checkpoints.");
                        return null;
                    }

                    ckRead++;
                }
            }

            // if checkpoints were expected but not all verified, enforce final verification using last state
            if (checkpointCount > 0 && ckRead < checkpointCount)
            {
                int msgLen = RedX.BuildAuthorityMessage(rKeyId32, ckRead, obsState, msg);
                var sig = sigs64xN.Slice(ckRead * RedX.DefaultAuthoritySigSize, RedX.DefaultAuthoritySigSize);
                if (!authorityPublicKey.VerifyData(msg.Slice(0, msgLen), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                {
                    RedX.DebugMint("Full-key authority signature verify failed at final checkpoint.");
                    return null;
                }
            }

            output.Position = 0;
            return output;
        }
    }

    /// <summary>
    /// Minting composite key: holds the full RedX key and authority key pair used to mint signed ciphertexts.<br/>
    /// Provides serialization for distribution/storage and can derive a verifier key without requiring the caller to handle ECDSA directly.
    /// </summary>
    public sealed class RedXMintingKey
    {
        /// <summary>
        /// Rehydrate a minting key from its serialized blob.<br/>
        /// Validates structural lengths and recomputes derived fields (key hash, inverse rows) from the stored key material.
        /// </summary>
        //Shared/Static Members
        internal static RedXMintingKey FromBytes(ReadOnlySpan<byte> blob)
        {
            int off = 0;
            if (blob.Length < 1 + 1 + 4) throw new ArgumentException("Minting key blob too small", nameof(blob));
            byte ver = blob[off++];
            if (ver != Version) throw new NotSupportedException($"Minting key version {ver} not supported");
            byte keyBlockSize = blob[off++];
            int keyLen = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(off, 4)); off += 4;
            int expectedLen = keyBlockSize * 256;
            if (keyLen != expectedLen) throw new InvalidOperationException("Minting key length mismatch");
            if (blob.Length < off + keyLen + 4) throw new ArgumentException("Minting key blob truncated", nameof(blob));

            var keyBytes = blob.Slice(off, keyLen).ToArray(); off += keyLen;

            int authPrivLen = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(off, 4)); off += 4;
            if (authPrivLen < 1 || blob.Length < off + authPrivLen + 4) throw new InvalidOperationException("Invalid authority private length");
            var authPriv = blob.Slice(off, authPrivLen).ToArray(); off += authPrivLen;

            int authPubLen = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(off, 4)); off += 4;
            if (authPubLen < 1 || blob.Length < off + authPubLen) throw new InvalidOperationException("Invalid authority public length");
            var authPub = blob.Slice(off, authPubLen).ToArray();

            var fullKey = RehydrateKey(keyBlockSize, keyBytes);
            return new RedXMintingKey(fullKey, authPriv, authPub);
        }
        private static RedXKey RehydrateKey(byte keyBlockSize, ReadOnlySpan<byte> keyBytes)
        {
            if (keyBlockSize == 0) throw new ArgumentOutOfRangeException(nameof(keyBlockSize));
            if (keyBytes.Length != keyBlockSize * 256) throw new ArgumentException("Key bytes length does not match block size", nameof(keyBytes));

            var key = RedXKey.RehydrateFromRawKeyBytes(keyBytes);
            if (key.keyBlockSize != keyBlockSize)
                throw new InvalidOperationException("Minting key block size mismatch");
            return key;
        }








        //======  FIELDS  ======
        private const byte Version = 1;








        //======  CONSTRUCTORS  ======
        internal RedXMintingKey(RedXKey fullKey, byte[] authorityPrivateKeyPkcs8, byte[] authorityPublicKeySpki)
        {
            FullKey = fullKey ?? throw new ArgumentNullException(nameof(fullKey));
            AuthorityPrivateKeyPkcs8 = authorityPrivateKeyPkcs8 ?? throw new ArgumentNullException(nameof(authorityPrivateKeyPkcs8));
            AuthorityPublicKeySpki = authorityPublicKeySpki ?? throw new ArgumentNullException(nameof(authorityPublicKeySpki));
        }








        //======  PROPERTIES  ======
        internal byte[] AuthorityPrivateKeyPkcs8 { get; }
        internal byte[] AuthorityPublicKeySpki { get; }
        internal RedXKey FullKey { get; }
        /// <summary>
        /// Authority public key (SPKI) paired with the private key.<br/>
        /// Used by verifiers to validate checkpoints.
        /// </summary>
        public ReadOnlyMemory<byte> AuthorityPublicKey => AuthorityPublicKeySpki;
        /// <summary>
        /// Exposes the full key for callers that still need symmetric operations.<br/>
        /// Provided as a read-only view to minimize accidental mutation.
        /// </summary>
        public RedXKey Key => FullKey;








        /// <summary>
        /// Derive a verifier key (verifying decryption key + authority public key) from this minting key.<br/>
        /// The verifier key is deterministic from the full key; this keeps minting flow simple while preserving separation of duties.
        /// </summary>
        //------ Public Methods -----
        //======  METHODS  ======
        public RedXVerifierKey CreateVerifierKey()
        {
            var verifyingKey = FullKey.CreateVerifyingDecryptionKey();
            return new RedXVerifierKey(verifyingKey, AuthorityPublicKeySpki);
        }

        /// <summary>
        /// Serialize the minting key to a byte blob for storage/transport.<br/>
        /// Layout (little-endian lengths): [ver:byte][keyBlockSize:byte][keyLen:int][keyBytes][authPrivLen:int][authPriv][authPubLen:int][authPub].
        /// </summary>
        public byte[] ToBytes()
        {
            int keyLen = FullKey.key.Length;
            int authPrivLen = AuthorityPrivateKeyPkcs8.Length;
            int authPubLen = AuthorityPublicKeySpki.Length;
            int total = 1 + 1 + 4 + keyLen + 4 + authPrivLen + 4 + authPubLen;
            var buf = new byte[total];
            int off = 0;

            buf[off++] = Version;
            buf[off++] = FullKey.keyBlockSize;
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), keyLen); off += 4;
            FullKey.key.AsSpan().CopyTo(buf.AsSpan(off, keyLen)); off += keyLen;
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), authPrivLen); off += 4;
            AuthorityPrivateKeyPkcs8.AsSpan().CopyTo(buf.AsSpan(off, authPrivLen)); off += authPrivLen;
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), authPubLen); off += 4;
            AuthorityPublicKeySpki.AsSpan().CopyTo(buf.AsSpan(off, authPubLen));

            return buf;
        }
    }

    /// <summary>
    /// Verifier composite key: holds the verifier key and authority public key required to decrypt and verify checkpoints.<br/>
    /// Does not include minting material or authority private key.
    /// </summary>
    public sealed class RedXVerifierKey
    {
        /// <summary>
        /// Rehydrate a verifier key from its serialized blob.<br/>
        /// Ensures structural integrity before constructing the verifier key and public key.
        /// </summary>
        //Shared/Static Members
        internal static RedXVerifierKey FromBytes(ReadOnlySpan<byte> blob)
        {
            int off = 0;
            if (blob.Length < 1 + 4) throw new ArgumentException("Verifier key blob too small", nameof(blob));
            byte ver = blob[off++];
            if (ver != Version) throw new NotSupportedException($"Verifier key version {ver} not supported");
            int verifierLen = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(off, 4)); off += 4;
            if (verifierLen < 1 || blob.Length < off + verifierLen + 4) throw new InvalidOperationException("Invalid verifier key length");
            var verifierBlob = blob.Slice(off, verifierLen); off += verifierLen;
            int authPubLen = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(off, 4)); off += 4;
            if (authPubLen < 1 || blob.Length < off + authPubLen) throw new InvalidOperationException("Invalid authority public length");
            var authPub = blob.Slice(off, authPubLen).ToArray();

            var verifyingKey = new RedXVerifyingDecryptionKey(verifierBlob);
            return new RedXVerifierKey(verifyingKey, authPub);
        }








        //======  FIELDS  ======
        private const byte Version = 1;








        //======  CONSTRUCTORS  ======
        internal RedXVerifierKey(RedXVerifyingDecryptionKey verifyingKey, byte[] authorityPublicKeySpki)
        {
            VerifyingKey = verifyingKey ?? throw new ArgumentNullException(nameof(verifyingKey));
            AuthorityPublicKeySpki = authorityPublicKeySpki ?? throw new ArgumentNullException(nameof(authorityPublicKeySpki));
        }








        //======  PROPERTIES  ======
        internal byte[] AuthorityPublicKeySpki { get; }
        /// <summary>
        /// Exposes the verifier key for decryption use.<br/>
        /// Provided as a read-only property to avoid accidental replacement.
        /// </summary>
        internal RedXVerifyingDecryptionKey Key => VerifyingKey;
        internal RedXVerifyingDecryptionKey VerifyingKey { get; }
        /// <summary>
        /// Authority public key (SPKI) used to verify checkpoints.<br/>
        /// Return type is ReadOnlyMemory to discourage mutation.
        /// </summary>
        public ReadOnlyMemory<byte> AuthorityPublicKey => AuthorityPublicKeySpki;








        /// <summary>
        /// Serialize the verifier key to a byte blob for storage/transport.<br/>
        /// Layout (little-endian lengths): [ver:byte][verifierLen:int][verifierBlob][authPubLen:int][authPub].
        /// </summary>
        //------ Public Methods -----
        //======  METHODS  ======
        public byte[] ToBytes()
        {
            var verifierBlob = VerifyingKey.ToBytes();
            int verifierLen = verifierBlob.Length;
            int authPubLen = AuthorityPublicKeySpki.Length;
            int total = 1 + 4 + verifierLen + 4 + authPubLen;
            var buf = new byte[total];
            int off = 0;
            buf[off++] = Version;
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), verifierLen); off += 4;
            verifierBlob.AsSpan().CopyTo(buf.AsSpan(off, verifierLen)); off += verifierLen;
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), authPubLen); off += 4;
            AuthorityPublicKeySpki.AsSpan().CopyTo(buf.AsSpan(off, authPubLen));
            return buf;
        }
    }

    /// <summary>
    /// Verifying decryption key used for verify/mint decryption and authority verification.
    /// Contains the master key hash, per-position nonces, and a blinded map from lookup tokens to plaintext bytes.
    /// Does not retain a copy of the original RedX key bytes after construction.
    /// This runtime-only type performs lookups to recover plaintext and verify checkpoints; it is internal implementation detail.
    /// </summary>
    internal sealed class RedXVerifyingDecryptionKey
    {
        //Shared/Static Members
        private static void DeriveNoncesAndMap(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> keyBytes, ReadOnlySpan<byte> keyHash, Span<ushort> nonceDest, Dictionary<uint, byte> map, int keyBlockSize)
        {
            int keyLength = keyBytes.Length;
            Span<byte> buf = stackalloc byte[seed.Length + 64 + 4];
            seed.CopyTo(buf);
            keyHash.CopyTo(buf.Slice(seed.Length, keyHash.Length));

            for (int i = 0; i < keyLength; i++)
            {
                BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(seed.Length + keyHash.Length, 4), i);
                var h = Blake3.Hasher.New();
                h.Update(buf);
                Span<byte> out16 = stackalloc byte[16];
                h.Finalize(out16);
                ushort nonce = MemoryMarshal.Read<ushort>(out16);
                nonceDest[i] = nonce;
                uint h32 = RedX.ComputeH32(keyHash, i, nonce);
                map[h32] = keyBytes[i];
            }
        }








        //======  FIELDS  ======
        private const byte VerifyingKeyVersionCompact = 2; // compact seed+key format (current)








        private readonly Dictionary<uint, byte> chMap;
        private readonly bool compactSeeded;
        private readonly int keyBlockSize;
        private readonly int keyLength;
        private readonly byte[] seed;              // present when derived deterministically (compact form)








        internal readonly Memory<byte> keyHash;        // 64-byte Blake3 digest
        internal readonly Memory<ushort> nonces;       // one nonce per flat index (stored)








        // chPublicParam removed: chameleon-hash was removed from the verifier-key design
        /// <summary>
        /// Build a verifier key from a full key.<br/>
        /// Instead of a chameleon hash, uses Blake3-derived 32-bit tokens bound to (index, nonce) pairs.<br/>
        /// This preserves the mint/verify behavior while removing chameleon-hash dependency and making lookups reproducible.
        /// </summary>
        //======  CONSTRUCTORS  ======
        public RedXVerifyingDecryptionKey(RedXKey key)
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

            // 2) choose seed and derive deterministic per-index nonces
            seed = RandomNumberGenerator.GetBytes(16);
            compactSeeded = true;
            nonces = new ushort[keyLength];
            chMap = new Dictionary<uint, byte>(keyLength);
            DeriveNoncesAndMap(seed, key.key.AsSpan(), keyHash.Span, nonces.Span, chMap, keyBlockSize);
        }

        /// <summary>
        /// Rehydrate directly from the ToBytes() blob.<br/>
        /// Rehydrate directly from the ToBytes() blob.<br/>
        /// This constructor trusts the blob and performs minimal validation; callers should ensure authenticity before passing it in.
        /// </summary>
        public RedXVerifyingDecryptionKey(ReadOnlySpan<byte> blob)
        {
            int off = 0;
            if (blob.Length < 1 + 4 + 1 + 1)
                throw new ArgumentException("Verifier key blob too small", nameof(blob));
            byte version = blob[off++];
            if (version != VerifyingKeyVersionCompact)
                throw new NotSupportedException($"Verifier key version {version} not supported");

            keyLength = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(off, 4)); off += 4;
            keyBlockSize = blob[off++]; // rows
            int seedLen = blob[off++];
            if (seedLen < 1 || blob.Length < off + seedLen + keyLength)
                throw new InvalidOperationException("Verifier key blob truncated");
            seed = blob.Slice(off, seedLen).ToArray(); off += seedLen;
            compactSeeded = true;

            // remaining are key bytes
            var keyBytes = blob.Slice(off, keyLength).ToArray();
            off += keyLength;

            // recompute key hash from key bytes
            keyHash = new byte[64];
            var b3 = Blake3.Hasher.New();
            b3.Update(keyBytes);
            b3.Finalize(keyHash.Span);

            // derive nonces and map deterministically
            nonces = new ushort[keyLength];
            chMap = new Dictionary<uint, byte>(keyLength);
            DeriveNoncesAndMap(seed, keyBytes.AsSpan(), keyHash.Span, nonces.Span, chMap, keyBlockSize);
        }








        /// <summary>
        /// Returns the verifier key as a persistable byte array (compact v2).<br/>
        /// Layout v2: [ver:byte=2][keyLen:int32][blockSize:byte][seedLen:byte][seed][keyBytes[keyLen]].<br/>
        /// </summary>
        //------ Public Methods -----
        //======  METHODS  ======
        public byte[] ToBytes()
        {
            if (!compactSeeded || seed == null)
                throw new InvalidOperationException("Lookup key serialization requires a compact seed.");

            // Compact v2 layout using stored seed and key bytes reconstructed by index
            byte version = VerifyingKeyVersionCompact;
            byte seedLen = (byte)seed.Length;

            // Rebuild key bytes in index order using current nonces/map
            var keyBytes = new byte[keyLength];
            var ns = nonces.Span;
            for (int i = 0; i < keyLength; i++)
            {
                uint h32 = RedX.ComputeH32(keyHash.Span, i, ns[i]);
                keyBytes[i] = chMap[h32];
            }

            int total = 1                      // version
                      + 4                      // keyLen
                      + 1                      // blockSize
                      + 1 + seedLen            // seedLen + seed
                      + keyBytes.Length;       // key bytes

            var blob = new byte[total];
            int off = 0;
            blob[off++] = version;
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(off, 4), keyLength); off += 4;
            blob[off++] = (byte)keyBlockSize;
            blob[off++] = seedLen;
            seed.AsSpan().CopyTo(blob.AsSpan(off, seedLen)); off += seedLen;
            keyBytes.AsSpan().CopyTo(blob.AsSpan(off, keyBytes.Length));
            return blob;
        }

        // ——————————————————————————————————————————————
        // decryption
        /// <summary>
        /// Replay a key-row offset stream into plaintext using the verifier key.
        /// Supports compact or header-based nonce encodings for small control streams, and interference catalyst mixing to resist replay.<br/>
        /// Returns a new BufferStream positioned at 0 or null on header rejection when rejectCompactHeader is true.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapData(BufferStream mapped, short startLocation, ReadOnlySpan<byte> verifyingKeyLock, ReadOnlySpan<byte> intCat = default, int count = -1, bool rejectCompactHeader = false)
        {
            // keyLength is keyBlockSize * 256
            int start = ((ushort)startLocation) % this.keyLength;
            int curRow = start / 256;
            int curCol = start % 256;
            int intCatLen = intCat.Length;
            int blockSz = keyBlockSize;

            var output = new BufferStream();
            var bx = new JumpGenerator(keyHash.Span, 1, intCat);
            var noncesSpan = nonces.Span;           // masked nonces from verifier key
            var map = chMap;
            Span<byte> hashBuf = stackalloc byte[4];
            var streamLength = mapped.Length;
            var streamPos = mapped.Position;

            // If a nonce map header was written (dictionary, RLE), or a compact
            // marker, decode it when the caller provided an explicit count. The
            // MapData(vKey, ...) encoding writes either a compact marker+payload
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
                        if (rejectCompactHeader)
                            return null;
                        // compact mode: remaining "count" bytes are the XOR'd payload
                        var buf = new byte[count];
                        for (int i = 0; i < count; i++) buf[i] = (byte)mapped.ReadByte();
                        // derive keystream and unmask into a BufferStream to return
                        var ks = new byte[count];
                        using (var xof = new Blake3XofReader(keyHash.Span, verifyingKeyLock))
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

                // determine nonce: prefer per-position nonce from the encoded header
                // (if present), otherwise fallback to the verifier key's stored nonce for the flat index
                ushort r = perPositionNonces != null && i < perPositionNonces.Length ? perPositionNonces[i] : noncesSpan[flatIndex];

                // compute Blake3-derived lookup value to recover plaintext
                uint h32 = RedX.ComputeH32(keyHash.Span, flatIndex, r);

                if (!map.TryGetValue(h32, out byte plain))
                    throw new CryptographicException($"verifier lookup failed at index {flatIndex}");

                // undo interference catalyst mixing
                if (intCatLen > 0)
                    plain = (byte)((256 + plain - i - intCat[i % intCatLen]) % 256);

                output.WriteByte(plain);

                // advance cursor
                curCol = newCol;
                curRow = (curRow + 1) % blockSz;
            }

            output.Position = 0;
            return output;
        }

        /// <summary>
        /// Replay a key-row offset stream into plaintext while enforcing authority signatures (verify context).<br/>
        /// Observer state is updated with both landing bytes and encoded distances so signatures bind to the exact ciphertext evolution.<br/>
        /// Returns null on any signature failure to ensure provenance is mandatory.
        /// </summary>
        /// <summary>
        /// Decrypt with authority verification using the full key (mirrors verifier-key path but leverages the full permutation).<br/>
        /// Observer state is recomputed in lockstep and each checkpoint signature is verified before plaintext is emitted further.<br/>
        /// Returns null on signature failure to avoid emitting unverified plaintext.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapDataWithAuthority(BufferStream mapped, short startLocation, ReadOnlySpan<byte> intCat, int checkpointInterval, int checkpointCount, ReadOnlySpan<byte> sigs64xN, ECDsa authorityPublicKey, ReadOnlySpan<byte> rKeyId32, int count = -1)
        {
            if (authorityPublicKey == null) throw new ArgumentNullException(nameof(authorityPublicKey));
            if (checkpointCount < 0) throw new ArgumentOutOfRangeException(nameof(checkpointCount));
            if (checkpointCount > 0)
            {
                if (checkpointInterval <= 0) throw new ArgumentOutOfRangeException(nameof(checkpointInterval));
                if (sigs64xN.Length < checkpointCount * RedX.DefaultAuthoritySigSize)
                    throw new ArgumentException("sigs64xN too small", nameof(sigs64xN));
                if (rKeyId32.Length != 32) throw new ArgumentException("rKeyId32 must be 32 bytes", nameof(rKeyId32));
            }

            int start = ((ushort)startLocation) % keyLength;
            int curRow = start / 256;
            int curCol = start % 256;
            int intCatLen = intCat.Length;

            var bx = new JumpGenerator(keyHash.Span, 1, intCat);
            Span<byte> obsState = stackalloc byte[RedX.ObserverStateSize];
            obsState.Clear();
            uint step = 0;
            int ckRead = 0;

            Span<byte> msg = stackalloc byte[RedX.AuthorityDomainBytes.Length + 32 + 4 + RedX.ObserverStateSize];
            var noncesSpan = nonces.Span;
            var map = chMap;

            var output = new BufferStream();

            for (int i = 0; (count < 0 || i < count) && mapped.Position < mapped.Length; i++)
            {
                int dist = mapped.ReadByte();
                if (dist < 0) break;

                ushort jump = bx.NextJump16();
                int colJump = jump & 0xFF;
                int rowJump = (jump >> 8) % keyBlockSize;
                curRow = (curRow + rowJump) % keyBlockSize;
                curCol = (curCol + colJump) & 0xFF;

                // landing byte via verifier map
                int landingFlat = curRow * 256 + curCol;
                uint h32Landing = RedX.ComputeH32(keyHash.Span, landingFlat, noncesSpan[landingFlat]);
                if (!map.TryGetValue(h32Landing, out byte landing))
                {
                    RedX.DebugMint($"Verifier landing lookup failed at index {landingFlat}");
                    throw new CryptographicException($"Verifier landing lookup failed at index {landingFlat}");
                }

                int mixIdx = (int)(step & 31);
                obsState[mixIdx] ^= landing;
                obsState[(mixIdx + 11) & 31] ^= (byte)jump;
                obsState[(mixIdx + 17) & 31] ^= (byte)(jump >> 8);
                obsState[(mixIdx + 23) & 31] ^= (byte)step;
                step++;

                int newCol = (curCol + dist) & 0xFF;
                // bind authority state to the distance encoding and resulting column
                obsState[(mixIdx + 5) & 31] ^= (byte)dist;
                obsState[(mixIdx + 7) & 31] ^= (byte)newCol;

                int flatIndex = curRow * 256 + newCol;
                uint h32 = RedX.ComputeH32(keyHash.Span, flatIndex, noncesSpan[flatIndex]);
                if (!map.TryGetValue(h32, out byte plain))
                {
                    RedX.DebugMint($"Verifier lookup failed at index {flatIndex}");
                    throw new CryptographicException($"Verifier lookup failed at index {flatIndex}");
                }

                if (intCatLen > 0)
                    plain = (byte)((256 + plain - i - intCat[i % intCatLen]) % 256);

                curCol = newCol;
                curRow = (curRow + 1) % keyBlockSize;

                output.WriteByte(plain);

                if (checkpointCount > 0 && ((i + 1) % checkpointInterval) == 0 && ckRead < checkpointCount)
                {
                    int msgLen = RedX.BuildAuthorityMessage(rKeyId32, ckRead, obsState, msg);
                    var sig = sigs64xN.Slice(ckRead * RedX.DefaultAuthoritySigSize, RedX.DefaultAuthoritySigSize);
                    if (!authorityPublicKey.VerifyData(msg.Slice(0, msgLen), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    {
                        RedX.DebugMint($"verifier authority signature verify failed at checkpoint {ckRead}.");
                        return null;
                    }
                    ckRead++;
                }
            }

            if (checkpointCount > 0 && ckRead < checkpointCount)
            {
                int msgLen = RedX.BuildAuthorityMessage(rKeyId32, ckRead, obsState, msg);
                var sig = sigs64xN.Slice(ckRead * RedX.DefaultAuthoritySigSize, RedX.DefaultAuthoritySigSize);
                if (!authorityPublicKey.VerifyData(msg.Slice(0, msgLen), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                {
                    RedX.DebugMint("verifier authority signature verify failed at final checkpoint.");
                    return null;
                }
            }

            output.Position = 0;
            return output;
        }
    }
}
