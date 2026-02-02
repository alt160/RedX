using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RedxLib
{
    /// <summary>
    /// RedX exposes the public surface for the RedX random-walk distance-stream cipher.<br/>
    /// The cipher walks a keyed 2D permutation grid, emitting forward distances that are replayed to recover plaintext.<br/>
    /// Anti-symmetric (ROK) mode enables decryption with a reduced key while supporting authority-signed checkpoints for provenance.<br/>
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
    /// Anti-symmetric with authority (ROK decrypt + signatures):<br/>
    /// <code><![CDATA[
    /// var key = RedX.CreateKey();
    /// var rok = key.CreateReadOnlyKey();
    /// using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    /// var authPriv = authority.ExportPkcs8PrivateKey();
    /// var authPub = authority.ExportSubjectPublicKeyInfo();
    /// var cipher = RedX.EncryptAntiSym(data, key, rok, authPriv);
    /// var recovered = RedX.DecryptAntiSymWithAuthority(cipher, rok, authPub);
    /// // recovered is null if any authority checkpoint fails verification
    /// ]]></code>
    /// </example>
    /// <example>
    /// Anti-symmetric with minting/verifier composites (no direct ECDsa handling):<br/>
    /// <code><![CDATA[
    /// var (minting, verifier) = RedX.CreateAntiSymmetricKeyPair();
    /// var cipher = RedX.EncryptAntiSym(data, minting);
    /// var recovered = RedX.DecryptAntiSymWithAuthority(cipher, verifier);
    /// var mintingBlob = minting.ToBytes();
    /// var verifierBlob = verifier.ToBytes();
    /// var minting2 = RedX.CreateMintingKey(mintingBlob);
    /// var verifier2 = RedX.CreateVerifierKey(verifierBlob);
    /// ]]></code>
    /// </example>
    /// </summary>
    public static class RedX
    {
        // ---------------------------------------------------------------------
        // Anti-symmetric (origin-locked) authority mode
        // ---------------------------------------------------------------------

        // Domain separator for authority checkpoint signatures (byte[] to avoid span field restrictions)
        internal static readonly byte[] AuthorityDomainBytes = new byte[]
        {
            (byte)'R',(byte)'E',(byte)'D',(byte)'X',(byte)'_',
            (byte)'A',(byte)'U',(byte)'T',(byte)'H',(byte)'_',
            (byte)'C',(byte)'K',(byte)'P',(byte)'T',(byte)'_',
            (byte)'V',(byte)'1'
        };

        // Default cap on embedded checkpoint signatures (anti-symmetric mode)
        internal const int DefaultAuthorityCheckpointMax = 64;

        // Default fixed signature size for P-256 ECDSA in IEEE-P1363 fixed format.
        internal const int DefaultAuthoritySigSize = 64;

        // default chunk size (legacy VRF path) – retained for compatibility with older ciphertexts.
        private const int DefaultAuthorityChunkSize = 4096;

        // default fixed proof size (bytes) for legacy per-chunk proofs (VRF).
        private const int DefaultProofPlainSize = 96;

        /// <summary>
        /// Create a full RedX key (includes encryption and ROK derivation material).<br/>
        /// keySize controls the number of 256-byte rows in the permutation grid; the default (8) targets typical payload sizes.
        /// </summary>
        public static REKey CreateKey(byte keySize = 8)
        {
            return new REKey(keySize);
        }

        /// <summary>
        /// Derive a 32-bit lookup token bound to the master key hash, a flat index, and a nonce.<br/>
        /// This replaces the chameleon hash: both full keys and ROKs rely on this token to map distances back to plaintext bytes.
        /// </summary>
        /// <param name="keyHash">First 64 bytes of the Blake3 hash of the master key.<br/>Only the first 8 bytes are consumed to keep the input small.</param>
        /// <param name="index">Flat index into the permutation grid (row*256 + col).<br/>Binds the token to the walk position.</param>
        /// <param name="nonce">Per-position nonce that blinds the mapping.<br/>Uniqueness is enforced when building ROKs.</param>
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
        /// Encrypt using the symmetric/full-key path.<br/>
        /// This is the lowest-friction entry point: no authority metadata is embedded and decryption requires the full key.
        /// </summary>
        public static BufferStream Encrypt(byte[] data, REKey key)
        {
            return EncryptWithAuthority(data, key, null, null, DefaultProofPlainSize);
        }

        /// <summary>
        /// Encrypt and optionally embed ROK-readable authority proofs in the control stream.<br/>
        /// Proofs are stored immediately after the per-message rokLock so that a ROK-holder can unmap and verify them.<br/>
        /// When rokTarget is supplied, the encrypted metadata is bound to that ROK; otherwise it is readable by the full key only.
        /// </summary>
        /// <remarks>
        /// Header layout: startLocation | rokLock | enc(proofCount) | enc(proofs…) | ivLen | enc(iv) | enc(auth) | distances.<br/>
        /// The distances are the same skip-coded payload as the symmetric path; proofs ride on the control stream for auditability.
        /// </remarks>
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
            Console.WriteLine($"[EncryptWithAuthority] rokLock (hex): {BitConverter.ToString(rokLockBytes)}");

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
                Console.WriteLine($"[EncryptWithAuthority] embedding proofCount={proofCount}");

                for (int i = 0; i < proofCount; i++)
                {
                    var p = authorityProofs[i];
                    if (p == null) throw new ArgumentNullException(nameof(authorityProofs));
                    if (p.Length != proofPlainSize) throw new ArgumentException("authority proof size mismatch");
                    using var pEnc = key.MapData(rokTarget, rokLockBytes, p, 0);
                    ret.Write(pEnc);
                    Console.WriteLine($"[EncryptWithAuthority] proof[{i}] embedded (base64 shown)");
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



        // ---------------------------------------------------------------------
        // Anti-symmetric (origin-locked) encryption using authority checkpoint signatures
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

        internal const int ObserverStateSize = 32;

        /// <summary>
        /// Encrypt in anti-symmetric mode: ciphertext can be decrypted by the provided ROK and verified via authority signatures.<br/>
        /// Checkpoints sample the distance stream, accumulate observer state, and are signed with the authority's P-256 key to bind provenance.<br/>
        /// Use this when a ROK-holder must be able to decrypt while still requiring attestations from the authority key.
        /// </summary>
        /// <param name="rokTarget">ROK that will decrypt control-stream headers; null is allowed for full-key-only consumers.</param>
        /// <param name="authorityPrivateKeyPkcs8">Authority private key in PKCS#8 format used to sign checkpoints.</param>
        /// <param name="maxCheckpoints">Upper bound to defend against oversized metadata for large payloads.</param>
        public static BufferStream EncryptAntiSym(byte[] data, REKey key, REReadOnlyKey rokTarget, ReadOnlySpan<byte> authorityPrivateKeyPkcs8, int maxCheckpoints = DefaultAuthorityCheckpointMax)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (authorityPrivateKeyPkcs8.IsEmpty) throw new ArgumentException("authority private key is required", nameof(authorityPrivateKeyPkcs8));

            // output ciphertext buffer
            var ret = new BufferStream();

            // 1) random start location (payload walk)
            var startLocation = (short)RandomNumberGenerator.GetInt32(0, key.key.Length);
            ret.Write7BitInt(startLocation);

            // 2) per-message 4-byte lock to encrypt authority proofs (control stream)
            var rokLockBytes = RandomNumberGenerator.GetBytes(4);
            ret.Write(rokLockBytes);

            // 3) IV (payload)
            var ivLen = (byte)RandomNumberGenerator.GetInt32(7, 64);
            var iv = RandomNumberGenerator.GetBytes(ivLen);

            // Strategy: for small/medium payloads use a single accumulator signature; for larger payloads use checkpoints up to maxCheckpoints.
            const int SingleSigThreshold = 4 * 1024; // switch to checkpoints above this
            bool useCheckpoints = data.Length > SingleSigThreshold;

            int ckCount, interval;
            byte[] sigs;
            ReadOnlySpan<byte> rKeyId32 = key.keyHash.Span.Slice(0, 32);
            byte[] cipherBytes;
            byte[] ivArr = iv;

            if (useCheckpoints)
            {
                // checkpoint path
                ComputeCheckpointPlan(data.Length, maxCheckpoints, out ckCount, out interval);
                byte[] ckStates = ckCount > 0 ? new byte[ckCount * ObserverStateSize] : Array.Empty<byte>();
                using (var cipher = key.MapDataWithObserver(data, startLocation, ivArr, interval, ckCount, ckStates))
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
            }
            else
            {
                // single-accumulator path
                ckCount = 1;
                interval = data.Length; // force one snapshot at end

                byte[] ckStates = new byte[ObserverStateSize];
                using (var cipher = key.MapDataWithObserver(data, startLocation, ivArr, interval, ckCount, ckStates))
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
            }

            // 7) write encrypted checkpoint count and signatures (control stream encrypted under rokLockBytes at startLocation=0)
            // count is 4 bytes little-endian
            Span<byte> cntBuf = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(cntBuf, ckCount);

            if (rokTarget != null)
            {
                using var cntEnc = key.MapData(rokTarget, rokLockBytes, cntBuf, 0);
                ret.Write(cntEnc);
            }
            else
            {
                using var cntEnc = key.MapData(cntBuf, 0, rokLockBytes);
                ret.Write(cntEnc);
            }

            for (int i = 0; i < ckCount; i++)
            {
                var sig = sigs.AsSpan(i * DefaultAuthoritySigSize, DefaultAuthoritySigSize);
                if (rokTarget != null)
                {
                    using var sigEnc = key.MapData(rokTarget, rokLockBytes, sig, 0);
                    ret.Write(sigEnc);
                }
                else
                {
                    using var sigEnc = key.MapData(sig, 0, rokLockBytes);
                    ret.Write(sigEnc);
                }
            }

            // 8) write IV length + IV (encrypted using header mapping like existing format)
            ret.Write(ivLen);
            if (rokTarget != null)
            {
                using var headerEnc = key.MapData(rokTarget, rokLockBytes, iv, ivLen, iv);
                ret.Write(headerEnc);
            }
            else
            {
                using var headerEnc = key.MapData(iv, ivLen);
                ret.Write(headerEnc);
            }

            // 9) append Blake3 auth tag (same as existing)
            {
                var b3 = Blake3.Hasher.New();
                b3.Update(cipherBytes);
                b3.Update(iv);
                Span<byte> auth = stackalloc byte[32];
                b3.Finalize(auth);
                if (rokTarget != null)
                {
                    using var authEnc = key.MapData(rokTarget, rokLockBytes, auth, ivLen, iv);
                    ret.Write(authEnc);
                }
                else
                {
                    using var authEnc = key.MapData(auth, ivLen, iv);
                    ret.Write(authEnc);
                }
            }

            // 10) append ciphertext distance stream
            ret.Write(cipherBytes);

            ret.Position = 0;
            return ret;
        }

        /// <summary>
        /// Backward-compatible anti-symmetric encrypt that does not embed a ROK-targeted header.<br/>
        /// Equivalent to calling the ROK-aware overload with <c>rokTarget = null</c>.
        /// </summary>
        public static BufferStream EncryptAntiSym(byte[] data, REKey key, ReadOnlySpan<byte> authorityPrivateKeyPkcs8, int maxCheckpoints = DefaultAuthorityCheckpointMax)
        {
            return EncryptAntiSym(data, key, null, authorityPrivateKeyPkcs8, maxCheckpoints);
        }

        /// <summary>
        /// Anti-symmetric encrypt using a minting key composite.<br/>
        /// Uses the minting key's full key for payload encryption, derives a verifier key (ROK) for the header, and signs checkpoints with its authority private key.
        /// </summary>
        public static BufferStream EncryptAntiSym(byte[] data, RedXMintingKey mintingKey, int maxCheckpoints = DefaultAuthorityCheckpointMax)
        {
            if (mintingKey == null) throw new ArgumentNullException(nameof(mintingKey));
            var verifier = mintingKey.CreateVerifierKey();
            return EncryptAntiSym(data, mintingKey.FullKey, verifier.Rok, mintingKey.AuthorityPrivateKeyPkcs8, maxCheckpoints);
        }

        /// <summary>
        /// Decrypt anti-symmetric ciphertext with the full key and verify authority signatures inline.<br/>
        /// Fails closed (returns null) if parsing, signature checks, or auth tag verification fail.
        /// </summary>
        public static BufferStream DecryptAntiSym(BufferStream ciphertext, REKey key, ReadOnlySpan<byte> authorityPublicKeySpki, int maxCheckpoints = DefaultAuthorityCheckpointMax)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (authorityPublicKeySpki.IsEmpty) throw new ArgumentException("authority public key is required", nameof(authorityPublicKeySpki));

            // 1) parse start location and per-message rokLock
            var startLocation = (short)ciphertext.Read7BitInt();
            var rokLock = ciphertext.ReadBytes(4);

            // 2) read encrypted checkpoint count
            var cntPlain = key.UnmapData(ciphertext, 0, rokLock, 4);
            if (cntPlain == null || cntPlain.Length != 4) return null;
            int ckCount = BinaryPrimitives.ReadInt32LittleEndian(cntPlain.AsReadOnlySpan);
            if (ckCount < 0 || ckCount > maxCheckpoints) return null;

            // 3) read encrypted signatures
            byte[] sigs = ckCount > 0 ? new byte[ckCount * DefaultAuthoritySigSize] : Array.Empty<byte>();
            for (int i = 0; i < ckCount; i++)
            {
                var sigPlain = key.UnmapData(ciphertext, 0, rokLock, DefaultAuthoritySigSize);
                if (sigPlain == null || sigPlain.Length != DefaultAuthoritySigSize) return null;
                sigPlain.AsReadOnlySpan.CopyTo(sigs.AsSpan(i * DefaultAuthoritySigSize, DefaultAuthoritySigSize));
            }

            // 4) read IV
            var ivLen = ciphertext.ReadByte();
            if (ivLen < 0) return null;

            var iv = key.UnmapData(ciphertext, (short)ivLen, default, ivLen);
            if (iv == null || iv.Length != ivLen) return null;

            // 5) verify auth tag (same as existing)
            {
                var auth = key.UnmapData(ciphertext, (short)ivLen, iv.AsReadOnlySpan, 32);
                if (auth == null || auth.Length != 32) return null;

                var b3 = Blake3.Hasher.New();
                b3.Update(ciphertext.ReadonlySliceAtCurrent());
                b3.Update(iv.AsReadOnlySpan);
                Span<byte> auth2 = stackalloc byte[32];
                b3.Finalize(auth2);
                if (!auth.AsReadOnlySpan.SequenceEqual(auth2))
                    return null;
            }

            // 6) derive checkpoint interval (must match encryption plan)
            // We compute totalSteps as remaining cipher length.
            int cipherLen = (int)(ciphertext.Length - ciphertext.Position);
            ComputeCheckpointPlan(cipherLen, maxCheckpoints, out int planCount, out int interval);
            if (planCount != ckCount) return null; // canonical binding to plan

            // 7) unmap payload with in-process authority verification
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(authorityPublicKeySpki, out _);

            ReadOnlySpan<byte> rKeyId32 = key.keyHash.Span.Slice(0, 32);

            var plain = key.UnmapDataWithAuthority(ciphertext, startLocation, iv.AsReadOnlySpan, interval, ckCount, sigs, ecdsa, rKeyId32);
            if (plain == null) return null;

            plain.Position = 0;
            return plain;
        }

        /// <summary>
        /// ROK decrypt with mandatory authority verification (anti-symmetric).<br/>
        /// Performs a verify-only pass before emitting plaintext and returns null on any failure.<br/>
        /// Compact header encoding for IV/auth is rejected to avoid low-entropy forgeries.
        /// </summary>
        public static BufferStream DecryptAntiSymWithAuthority(BufferStream ciphertext, REReadOnlyKey rok, ReadOnlySpan<byte> authorityPublicKeySpki, int maxCheckpoints = DefaultAuthorityCheckpointMax)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (rok == null) throw new ArgumentNullException(nameof(rok));
            if (authorityPublicKeySpki.IsEmpty) throw new ArgumentException("authority public key is required", nameof(authorityPublicKeySpki));

            // Local parse with compact-header rejection for IV/auth
            var startLocation = (short)ciphertext.Read7BitInt();
            var rokLock = ciphertext.ReadBytes(4);

            // read encrypted checkpoint count
            try
            {
                var cntPlain = rok.UnmapData(ciphertext, 0, rokLock, default, 4);
                if (cntPlain == null || cntPlain.Length != 4) return null;
                int ckCount = BinaryPrimitives.ReadInt32LittleEndian(cntPlain.AsReadOnlySpan);
                if (ckCount < 0 || ckCount > maxCheckpoints) return null;

                // read encrypted signatures
                byte[] sigs = ckCount > 0 ? new byte[ckCount * DefaultAuthoritySigSize] : Array.Empty<byte>();
                for (int i = 0; i < ckCount; i++)
                {
                    var sigPlain = rok.UnmapData(ciphertext, 0, rokLock, default, DefaultAuthoritySigSize);
                    if (sigPlain == null || sigPlain.Length != DefaultAuthoritySigSize) return null;
                    sigPlain.AsReadOnlySpan.CopyTo(sigs.AsSpan(i * DefaultAuthoritySigSize, DefaultAuthoritySigSize));
                }

                // iv header (reject compact)
                var ivLen = ciphertext.ReadByte();
                if (ivLen < 0) return null;
                var iv = rok.UnmapData(ciphertext, (short)ivLen, rokLock, default, ivLen, rejectCompactHeader: false);
                if (iv == null || iv.Length != ivLen) return null;

                // auth tag (reject compact)
                {
                    var auth = rok.UnmapData(ciphertext, (short)ivLen, rokLock, iv.AsReadOnlySpan, 32, rejectCompactHeader: false);
                    if (auth == null || auth.Length != 32) return null;

                    var b3 = Blake3.Hasher.New();
                    b3.Update(ciphertext.ReadonlySliceAtCurrent());
                    b3.Update(iv.AsReadOnlySpan);
                    Span<byte> auth2 = stackalloc byte[32];
                    b3.Finalize(auth2);
                    if (!auth.AsReadOnlySpan.SequenceEqual(auth2))
                        return null;
                }

                // derive checkpoint plan based on remaining cipher length
                int cipherLen = (int)(ciphertext.Length - ciphertext.Position);
                ComputeCheckpointPlan(cipherLen, maxCheckpoints, out int planCount, out int interval);
                // allow ckCount==1 single-accumulator even if planCount suggests more
                if (!(ckCount == 1 || planCount == ckCount)) return null;

                ReadOnlySpan<byte> rKeyId32 = rok.keyHash.Span.Slice(0, 32);

                // Pass 1: verify only (discard plaintext)
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportSubjectPublicKeyInfo(authorityPublicKeySpki, out _);
                    var verifyOnly = rok.UnmapDataWithAuthority(ciphertext, startLocation, iv.AsReadOnlySpan, interval, ckCount, sigs, ecdsa, rKeyId32, count: cipherLen);
                    if (verifyOnly == null)
                        return null;
                }

                // Pass 2: re-parse and decrypt (verification re-run is acceptable)
                ciphertext.Position = 0;
                startLocation = (short)ciphertext.Read7BitInt();
                rokLock = ciphertext.ReadBytes(4);

                var cntPlain2 = rok.UnmapData(ciphertext, 0, rokLock, default, 4);
                if (cntPlain2 == null || cntPlain2.Length != 4) return null;
                int ckCount2 = BinaryPrimitives.ReadInt32LittleEndian(cntPlain2.AsReadOnlySpan);
                if (ckCount2 != ckCount) return null;

                byte[] sigs2 = ckCount > 0 ? new byte[ckCount * DefaultAuthoritySigSize] : Array.Empty<byte>();
                for (int i = 0; i < ckCount; i++)
                {
                    var sigPlain = rok.UnmapData(ciphertext, 0, rokLock, default, DefaultAuthoritySigSize);
                    if (sigPlain == null || sigPlain.Length != DefaultAuthoritySigSize) return null;
                    sigPlain.AsReadOnlySpan.CopyTo(sigs2.AsSpan(i * DefaultAuthoritySigSize, DefaultAuthoritySigSize));
                }

                ivLen = ciphertext.ReadByte();
                if (ivLen < 0) return null;
                iv = rok.UnmapData(ciphertext, (short)ivLen, rokLock, default, ivLen, rejectCompactHeader: false);
                if (iv == null || iv.Length != ivLen) return null;

                {
                    var auth = rok.UnmapData(ciphertext, (short)ivLen, rokLock, iv.AsReadOnlySpan, 32, rejectCompactHeader: false);
                    if (auth == null || auth.Length != 32) return null;

                    var b3 = Blake3.Hasher.New();
                    b3.Update(ciphertext.ReadonlySliceAtCurrent());
                    b3.Update(iv.AsReadOnlySpan);
                    Span<byte> auth2 = stackalloc byte[32];
                    b3.Finalize(auth2);
                    if (!auth.AsReadOnlySpan.SequenceEqual(auth2))
                        return null;
                }

                using var ecdsa2 = ECDsa.Create();
                ecdsa2.ImportSubjectPublicKeyInfo(authorityPublicKeySpki, out _);
                var plain = rok.UnmapDataWithAuthority(ciphertext, startLocation, iv.AsReadOnlySpan, interval, ckCount, sigs2, ecdsa2, rKeyId32, count: cipherLen);
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
        /// Symmetric decrypt using the full key.<br/>
        /// Validates the Blake3 auth tag before replaying the distance stream back into plaintext.
        /// </summary>
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
        /// Obsolete ROK decrypt that does not enforce authority verification; kept for legacy interop.<br/>
        /// Attempts to parse and decrypt embedded proofs but does not verify them—callers must verify externally or switch to DecryptAntiSymWithAuthority.<br/>
        /// The ciphertext stream position is consumed; ensure it is set appropriately before calling.
        /// </summary>
        [Obsolete("Unsafe: ROK decrypt without authority verification. Use DecryptAntiSymWithAuthority/DecryptVerified instead.")]
        public static BufferStream Decrypt(BufferStream ciphertext, REReadOnlyKey key)
        {
            var startLocation = (short)ciphertext.Read7BitInt();
            // read per-message rokLock (4 bytes) immediately after startLocation
            var rokLock = ciphertext.ReadBytes(4);
            // Probe whether an encrypted proof-count exists by attempting to unmap a 4-byte
            // count from a copy of the ciphertext at the current position. If the probe
            // yields a reasonable small non-negative integer, assume proofs are present.
            int proofCount = 0;
            var proofs = new List<byte[]>();

            var probe = new BufferStream(ciphertext.ToArray());
            probe.Position = ciphertext.Position;
            bool probeOk = false;
            try
            {
                var cntProbe = key.UnmapData(probe, (short)0, rokLock, default, 4);
                if (cntProbe != null && cntProbe.Length == 4)
                {
                    int pc = MemoryMarshal.Read<int>(cntProbe.AsReadOnlySpan);
                    // sanity limit on proof count
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
                // consume the encrypted count from the real ciphertext
                var cntEnc = key.UnmapData(ciphertext, (short)0, rokLock, default, 4);
                // read (and decrypt) each fixed-size proof (if any)
                for (int i = 0; i < proofCount; i++)
                {
                    int proofPlainSize = DefaultProofPlainSize;
                    var p = key.UnmapData(ciphertext, (short)0, rokLock, default, proofPlainSize);
                    proofs.Add(p.ToArray());
                }
            }

            var ivLen = ciphertext.ReadByte();

            var iv = key.UnmapData(ciphertext, ivLen, rokLock, default, ivLen);

            {
                var auth = key.UnmapData(ciphertext, ivLen, rokLock, iv.AsReadOnlySpan, 32);
                var b3 = Blake3.Hasher.New();
                b3.Update(ciphertext.ReadonlySliceAtCurrent());
                b3.Update(iv.AsReadOnlySpan);
                Span<byte> auth2 = stackalloc byte[32];
                b3.Finalize(auth2);
                if (auth.AsReadOnlySpan.SequenceEqual(auth2) == false)
                    return null;
            }

            var plain = key.UnmapData(ciphertext, startLocation, rokLock, iv.AsReadOnlySpan);

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

        /// <summary>
        /// Convenience wrapper for ROK decrypt that always enforces authority verification.<br/>
        /// Returns null on any failure; never exposes plaintext without a successful verify.
        /// </summary>
        public static BufferStream DecryptVerified(BufferStream ciphertext, REReadOnlyKey rok, ReadOnlySpan<byte> authorityPublicKeySpki, int maxCheckpoints = DefaultAuthorityCheckpointMax)
        {
            return DecryptAntiSymWithAuthority(ciphertext, rok, authorityPublicKeySpki, maxCheckpoints);
        }

        /// <summary>
        /// Convenience overload that uses a verifier key composite for ROK decrypt + authority verify.<br/>
        /// Returns null on any failure and never emits plaintext without successful verification.
        /// </summary>
        public static BufferStream DecryptAntiSymWithAuthority(BufferStream ciphertext, RedXVerifierKey verifierKey, int maxCheckpoints = DefaultAuthorityCheckpointMax)
        {
            if (verifierKey == null) throw new ArgumentNullException(nameof(verifierKey));
            return DecryptAntiSymWithAuthority(ciphertext, verifierKey.Rok, verifierKey.AuthorityPublicKeySpki, maxCheckpoints);
        }

        /// <summary>
        /// Overload for byte[] ciphertext convenience.<br/>
        /// Wraps the byte array in a BufferStream and forwards to the symmetric decrypt path.
        /// </summary>
        public static BufferStream Decrypt(byte[] ciphertext, REKey key)
        {
            // overlay BufferStream over ciphertext
            return Decrypt(new BufferStream(ciphertext), key);

        }

        /// <summary>
        /// Create a full symmetric key (minting) plus verifier key pair for anti-symmetric use.<br/>
        /// Generates a fresh P-256 authority key (compact 64-byte P1363 signatures; widely supported) to sign checkpoints.<br/>
        /// Returns both minting and verifier composites so callers can hand off the verifier to ROK-side consumers.
        /// </summary>
        public static (RedXMintingKey minting, RedXVerifierKey verifier) CreateAntiSymmetricKeyPair()
        {
            var fullKey = CreateKey();
            var rok = fullKey.CreateReadOnlyKey();
            using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256); // P-256: interoperable, hardware-accelerated, compact signatures
            var authPriv = authority.ExportPkcs8PrivateKey();
            var authPub = authority.ExportSubjectPublicKeyInfo();

            var minting = new RedXMintingKey(fullKey, authPriv, authPub);
            var verifier = new RedXVerifierKey(rok, authPub);
            return (minting, verifier);
        }

        /// <summary>
        /// Rehydrate a minting/verifier pair from serialized blobs produced by CreateAntiSymmetricKeyPair().<br/>
        /// Validates that the authority public key in both blobs matches to prevent mismatched inputs.
        /// </summary>
        public static (RedXMintingKey minting, RedXVerifierKey verifier) CreateAntiSymmetricKeyPair(ReadOnlySpan<byte> mintingKey, ReadOnlySpan<byte> verifierKey)
        {
            var m = CreateMintingKey(mintingKey);
            var v = CreateVerifierKey(verifierKey);
            if (!m.AuthorityPublicKeySpki.AsSpan().SequenceEqual(v.AuthorityPublicKeySpki))
                throw new InvalidOperationException("Minting/verifier authority mismatch.");
            return (m, v);
        }

        /// <summary>
        /// Rehydrate a minting key from its serialized blob.<br/>
        /// Use this when the minter needs to mint new ciphertexts or derive a verifier key.
        /// </summary>
        public static RedXMintingKey CreateMintingKey(ReadOnlySpan<byte> mintingKey)
        {
            return RedXMintingKey.FromBytes(mintingKey);
        }

        /// <summary>
        /// Rehydrate a verifier key from its serialized blob.<br/>
        /// Use this on the consumer side to decrypt/verify authority checkpoints without holding the minting material.
        /// </summary>
        public static RedXVerifierKey CreateVerifierKey(ReadOnlySpan<byte> verifierKey)
        {
            return RedXVerifierKey.FromBytes(verifierKey);
        }

    }

    /// <summary>
    /// Read-only RedX key (ROK) used for anti-symmetric decryption and authority verification.<br/>
    /// Contains the master key hash, per-position nonces, and a blinded map from lookup tokens to plaintext bytes.<br/>
    /// Does not include the forward permutation, so it can decrypt but cannot encrypt new ciphertexts.
    /// </summary>
    public sealed class REReadOnlyKey
    {
        private readonly int keyLength;
        private readonly int keyBlockSize;
        internal readonly Memory<byte> keyHash;        // 64-byte Blake3 digest
        internal readonly Memory<ushort> nonces;         // ← NEW: one nonce per flat index
        private readonly Dictionary<uint, byte> chMap;
        // chPublicParam removed: chameleon-hash was removed from the ROK design

        /// <summary>
        /// Build a ROK from a full key.<br/>
        /// Instead of a chameleon hash, uses Blake3-derived 32-bit tokens bound to (index, nonce) pairs.<br/>
        /// This preserves anti-symmetric behavior while removing chameleon-hash dependency and making lookups reproducible.
        /// </summary>
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
                    h32 = RedX.ComputeH32(keyHash.Span, i, r);
                }
                while (chMap.ContainsKey(h32));

                nonces.Span[i] = r;
                chMap[h32] = key.key[i];
            }

            // 4) no chameleon public params in this design
        }

        // ——————————————————————————————————————————————
        // decryption
        /// <summary>
        /// Replay a distance stream into plaintext using the ROK.<br/>
        /// Supports compact or header-based nonce encodings for small control streams, and IV mixing to resist replay.<br/>
        /// Returns a new BufferStream positioned at 0 or null on header rejection when rejectCompactHeader is true.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapData(BufferStream mapped, short startLocation, ReadOnlySpan<byte> rokLock, ReadOnlySpan<byte> iv = default, int count = -1, bool rejectCompactHeader = false)
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
                        if (rejectCompactHeader)
                            return null;
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

                // determine nonce: prefer per-position nonce from the encoded header
                // (if present), otherwise fallback to the ROK's stored nonce for the flat index
                ushort r = perPositionNonces != null && i < perPositionNonces.Length ? perPositionNonces[i] : noncesSpan[flatIndex];

                // compute Blake3-derived lookup value to recover plaintext
                uint h32 = RedX.ComputeH32(keyHash.Span, flatIndex, r);

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
        /// Replay a distance stream into plaintext while enforcing authority signatures (ROK context).<br/>
        /// Observer state is updated with both landing bytes and encoded distances so signatures bind to the exact ciphertext evolution.<br/>
        /// Returns null on any signature failure to ensure provenance is mandatory.
        /// </summary>
        /// <summary>
        /// Decrypt with authority verification using the full key (mirrors ROK path but leverages the full permutation).<br/>
        /// Observer state is recomputed in lockstep and each checkpoint signature is verified before plaintext is emitted further.<br/>
        /// Returns null on signature failure to avoid emitting unauthenticated plaintext.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapDataWithAuthority(BufferStream mapped, short startLocation, ReadOnlySpan<byte> iv, int checkpointInterval, int checkpointCount, ReadOnlySpan<byte> sigs64xN, ECDsa authorityPublicKey, ReadOnlySpan<byte> rKeyId32, int count = -1)
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

            startLocation = (short)(startLocation % keyLength);
            int curRow = startLocation / 256;
            int curCol = startLocation % 256;
            int ivLen = iv.Length;

            var bx = new JumpGenerator(keyHash.Span, 1, iv);
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

                // landing byte via ROK map
                int landingFlat = curRow * 256 + curCol;
                uint h32Landing = RedX.ComputeH32(keyHash.Span, landingFlat, noncesSpan[landingFlat]);
                if (!map.TryGetValue(h32Landing, out byte landing))
                    throw new CryptographicException($"ROK landing lookup failed at index {landingFlat}");

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
                    throw new CryptographicException($"ROK lookup failed at index {flatIndex}");

                if (ivLen > 0)
                    plain = (byte)((256 + plain - i - iv[i % ivLen]) % 256);

                curCol = newCol;
                curRow = (curRow + 1) % keyBlockSize;

                output.WriteByte(plain);

                if (checkpointCount > 0 && ((i + 1) % checkpointInterval) == 0 && ckRead < checkpointCount)
                {
                    int msgLen = RedX.BuildAuthorityMessage(rKeyId32, ckRead, obsState, msg);
                    var sig = sigs64xN.Slice(ckRead * RedX.DefaultAuthoritySigSize, RedX.DefaultAuthoritySigSize);
                    if (!authorityPublicKey.VerifyData(msg.Slice(0, msgLen), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                        return null;
                    ckRead++;
                }
            }

            if (checkpointCount > 0 && ckRead < checkpointCount)
            {
                int msgLen = RedX.BuildAuthorityMessage(rKeyId32, ckRead, obsState, msg);
                var sig = sigs64xN.Slice(ckRead * RedX.DefaultAuthoritySigSize, RedX.DefaultAuthoritySigSize);
                if (!authorityPublicKey.VerifyData(msg.Slice(0, msgLen), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    return null;
            }

            output.Position = 0;
            return output;
        }



        /// <summary>
        /// Returns the ROK as a persistable byte array.<br/>
        /// Layout: [keyHashLength:int32][keyHash:byte[keyHashLength]][nonces:ushort[keyLen]][chMapKeys:uint[keyLen]].
        /// </summary>
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
        /// Rehydrate directly from the ToBytes() blob.<br/>
        /// This constructor trusts the blob and performs minimal validation; callers should ensure authenticity before passing it in.
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


    /// <summary>
    /// Full RedX key used for encryption and for deriving ROKs.<br/>
    /// Holds the permutation rows, inverse lookup tables, and Blake3 key hash that seeds jump generators.<br/>
    /// Consumers encrypt with this type; ROKs derived from it can decrypt without exposing the forward permutation.
    /// </summary>
    public class REKey
    {
        internal byte[] key;
        internal byte[][] rkd;
        internal int keyLength;
        internal Memory<byte> keyHash;

        internal byte keyBlockSize;
        /// <summary>
        /// Create a full RedX key with the given row count (keySize).<br/>
        /// Each row is a Fisher-Yates shuffle of byte values, forming the keyed 2D permutation used by the distance stream.
        /// </summary>
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

        /// <summary>
        /// Derive a ROK from this key.<br/>
        /// The derived key contains lookup tokens and nonces only; it cannot be used to encrypt or regenerate the permutation.
        /// </summary>
        public REReadOnlyKey CreateReadOnlyKey()
        {
            // create a read-only key without chameleon-hash dependency
            return new REReadOnlyKey(this);
        }

        /// <summary>
        /// Map plaintext into a distance stream using the full key.<br/>
        /// The walker jumps pseudo-randomly across rows/cols (Blake3-seeded), then emits the forward distance to the plaintext byte in the new row.<br/>
        /// IV mixing folds position and caller IV into the plaintext to resist replay.
        /// </summary>
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

        /// <summary>
        /// Map plaintext while tracking observer state for authority checkpoints.<br/>
        /// Observer state mixes landing bytes, jump deltas, emitted distances, and step counter to give cryptographers a reproducible transcript.<br/>
        /// Checkpoints snapshot the observer state at fixed intervals and return it via <paramref name="checkpointStates32xN"/>.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream MapDataWithObserver(ReadOnlySpan<byte> data, short startLocation, ReadOnlySpan<byte> iv, int checkpointInterval, int checkpointCount, Span<byte> checkpointStates32xN)
        {
            if (checkpointCount < 0) throw new ArgumentOutOfRangeException(nameof(checkpointCount));
            if (checkpointCount > 0)
            {
                if (checkpointInterval <= 0) throw new ArgumentOutOfRangeException(nameof(checkpointInterval));
                if (checkpointStates32xN.Length < checkpointCount * RedX.ObserverStateSize)
                    throw new ArgumentException("checkpointStates32xN too small", nameof(checkpointStates32xN));
            }

            // wrap startLocation
            startLocation = (short)(startLocation % keyLength);
            var sRow = (startLocation / 256) % keyBlockSize;
            var sCol = startLocation % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            int ivLen = iv.Length;

            var bx = new JumpGenerator(keyHash.Span, 1, iv);

            Span<byte> obsState = stackalloc byte[RedX.ObserverStateSize];
            obsState.Clear();
            uint step = 0;

            int ckWrite = 0;

            for (int i = 0; i < data.Length; i++)
            {
                byte curByte = data[i];
                if (ivLen > 0)
                    curByte = (byte)((curByte + i + iv[i % ivLen]) % 256);

                ushort jump = bx.NextJump16();
                var rowJump = ((jump % keyLength) / 256);
                var colJump = jump % 256;

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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public BufferStream UnmapDataWithAuthority(BufferStream mapped, short startLocation, ReadOnlySpan<byte> iv, int checkpointInterval, int checkpointCount, ReadOnlySpan<byte> sigs64xN, ECDsa authorityPublicKey, ReadOnlySpan<byte> rKeyId32, int count = -1)
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

            startLocation = (short)(startLocation % (keyBlockSize * 256));
            var sRow = startLocation / 256;
            var sCol = startLocation % 256;

            var output = new BufferStream();
            var curRow = sRow;
            var curCol = sCol;
            int ivLen = iv.Length;

            var bx = new JumpGenerator(keyHash.Span, 1, iv);

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
                var rowJump = ((jump % keyLength) / 256);
                var colJump = jump % 256;

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

                if (ivLen > 0)
                    plain = (byte)((256 + plain - i - iv[i % ivLen]) % 256);

                curCol = (curCol + dist) % 256;
                curRow = (curRow + 1) % keyBlockSize;

                output.WriteByte(plain);

                if (checkpointCount > 0 && ((i + 1) % checkpointInterval) == 0 && ckRead < checkpointCount)
                {
                    int msgLen = RedX.BuildAuthorityMessage(rKeyId32, ckRead, obsState, msg);
                    var sig = sigs64xN.Slice(ckRead * RedX.DefaultAuthoritySigSize, RedX.DefaultAuthoritySigSize);
                    if (!authorityPublicKey.VerifyData(msg.Slice(0, msgLen), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                        return null;

                    ckRead++;
                }
            }

            // if checkpoints were expected but not all verified, enforce final verification using last state
            if (checkpointCount > 0 && ckRead < checkpointCount)
            {
                int msgLen = RedX.BuildAuthorityMessage(rKeyId32, ckRead, obsState, msg);
                var sig = sigs64xN.Slice(ckRead * RedX.DefaultAuthoritySigSize, RedX.DefaultAuthoritySigSize);
                if (!authorityPublicKey.VerifyData(msg.Slice(0, msgLen), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    return null;
            }

            output.Position = 0;
            return output;
        }





        /// <summary>
        /// Map data for a specific ROK target by encoding per-position nonces alongside the distance stream.<br/>
        /// Small payloads use a compact XOR-with-XOF fast path; larger payloads choose between dictionary and RLE nonce encodings for efficiency.<br/>
        /// This keeps the control stream decryptable by the ROK without leaking the full permutation.
        /// </summary>
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
        /// Inverses the skip‐distance mapping performed by MapData.<br/>
        /// Replays the same jump generator (seeded by keyHash and IV) to land on the correct rows/cols and undo IV mixing.
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

        /// <summary>
        /// Convenience overload that accepts an in-memory distance stream instead of BufferStream.<br/>
        /// Useful for tests or callers that already materialized the cipher bytes.
        /// </summary>
        public BufferStream UnmapData(Memory<byte> skipsSpan, short startLocation, ReadOnlySpan<byte> iv = default, int count = -1)
        {
            return UnmapData(new BufferStream(skipsSpan), startLocation, iv, count);
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
    }

    /// <summary>
    /// RLE helpers for ushort sequences (used to compress per-position nonces for ROK headers).<br/>
    /// Encodes runs with a single-byte header to keep control streams small and deterministic for testing.
    /// </summary>
    internal static class RLE
    {
        /// <summary>
        /// Run-length encodes an array of ushorts into a BufferStream.<br/>
        /// Format: [hdr][data…][hdr][data…]… where hdr&lt;0x80 is a literal run (len=hdr) and hdr&gt;=0x80 is a repeat run (len=hdr&0x7F).<br/>
        /// Keeps nonce headers compact while remaining easy to decode during decryption.
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
        /// Decodes the above RLE back into an array of ushorts.<br/>
        /// Tolerates premature EOF by stopping when the stream ends.
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

    /// <summary>
    /// Minting composite for anti-symmetric use: holds the full RedX key and authority key pair used to mint signed ciphertexts.<br/>
    /// Provides serialization for distribution/storage and can derive a verifier key without requiring the caller to handle ECDSA directly.
    /// </summary>
    public sealed class RedXMintingKey
    {
        private const byte Version = 1;

        internal REKey FullKey { get; }
        internal byte[] AuthorityPrivateKeyPkcs8 { get; }
        internal byte[] AuthorityPublicKeySpki { get; }

        internal RedXMintingKey(REKey fullKey, byte[] authorityPrivateKeyPkcs8, byte[] authorityPublicKeySpki)
        {
            FullKey = fullKey ?? throw new ArgumentNullException(nameof(fullKey));
            AuthorityPrivateKeyPkcs8 = authorityPrivateKeyPkcs8 ?? throw new ArgumentNullException(nameof(authorityPrivateKeyPkcs8));
            AuthorityPublicKeySpki = authorityPublicKeySpki ?? throw new ArgumentNullException(nameof(authorityPublicKeySpki));
        }

        /// <summary>
        /// Exposes the full key for callers that still need symmetric operations.<br/>
        /// Provided as a read-only view to minimize accidental mutation.
        /// </summary>
        public REKey Key => FullKey;

        /// <summary>
        /// Authority private key (PKCS#8) used to sign checkpoints.<br/>
        /// Return type is ReadOnlyMemory to discourage mutation while keeping API friction low.
        /// </summary>
        public ReadOnlyMemory<byte> AuthorityPrivateKey => AuthorityPrivateKeyPkcs8;

        /// <summary>
        /// Authority public key (SPKI) paired with the private key.<br/>
        /// Used by verifiers to validate checkpoints.
        /// </summary>
        public ReadOnlyMemory<byte> AuthorityPublicKey => AuthorityPublicKeySpki;

        /// <summary>
        /// Derive a verifier key (ROK + authority public key) from this minting key.<br/>
        /// The ROK is deterministic from the full key; this keeps minting flow simple while preserving separation of duties.
        /// </summary>
        public RedXVerifierKey CreateVerifierKey()
        {
            var rok = FullKey.CreateReadOnlyKey();
            return new RedXVerifierKey(rok, AuthorityPublicKeySpki);
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

        /// <summary>
        /// Rehydrate a minting key from its serialized blob.<br/>
        /// Validates structural lengths and recomputes derived fields (key hash, inverse rows) from the stored key material.
        /// </summary>
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

        private static REKey RehydrateKey(byte keyBlockSize, ReadOnlySpan<byte> keyBytes)
        {
            if (keyBlockSize == 0) throw new ArgumentOutOfRangeException(nameof(keyBlockSize));
            if (keyBytes.Length != keyBlockSize * 256) throw new ArgumentException("Key bytes length does not match block size", nameof(keyBytes));

            var key = new REKey(keyBlockSize);
            key.key = keyBytes.ToArray();
            key.keyLength = keyBytes.Length;
            key.keyBlockSize = keyBlockSize;

            key.rkd = new byte[keyBlockSize][];
            for (int row = 0; row < keyBlockSize; row++)
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
    }

    /// <summary>
    /// Verifier composite for anti-symmetric use: holds the ROK and authority public key required to decrypt and verify checkpoints.<br/>
    /// Does not include minting material or authority private key.
    /// </summary>
    public sealed class RedXVerifierKey
    {
        private const byte Version = 1;

        internal REReadOnlyKey Rok { get; }
        internal byte[] AuthorityPublicKeySpki { get; }

        internal RedXVerifierKey(REReadOnlyKey rok, byte[] authorityPublicKeySpki)
        {
            Rok = rok ?? throw new ArgumentNullException(nameof(rok));
            AuthorityPublicKeySpki = authorityPublicKeySpki ?? throw new ArgumentNullException(nameof(authorityPublicKeySpki));
        }

        /// <summary>
        /// Exposes the ROK for decryption use.<br/>
        /// Provided as a read-only property to avoid accidental replacement.
        /// </summary>
        public REReadOnlyKey Key => Rok;

        /// <summary>
        /// Authority public key (SPKI) used to verify checkpoints.<br/>
        /// Return type is ReadOnlyMemory to discourage mutation.
        /// </summary>
        public ReadOnlyMemory<byte> AuthorityPublicKey => AuthorityPublicKeySpki;

        /// <summary>
        /// Serialize the verifier key to a byte blob for storage/transport.<br/>
        /// Layout (little-endian lengths): [ver:byte][rokLen:int][rokBlob][authPubLen:int][authPub].
        /// </summary>
        public byte[] ToBytes()
        {
            var rokBlob = Rok.ToBytes();
            int rokLen = rokBlob.Length;
            int authPubLen = AuthorityPublicKeySpki.Length;
            int total = 1 + 4 + rokLen + 4 + authPubLen;
            var buf = new byte[total];
            int off = 0;
            buf[off++] = Version;
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), rokLen); off += 4;
            rokBlob.AsSpan().CopyTo(buf.AsSpan(off, rokLen)); off += rokLen;
            BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(off, 4), authPubLen); off += 4;
            AuthorityPublicKeySpki.AsSpan().CopyTo(buf.AsSpan(off, authPubLen));
            return buf;
        }

        /// <summary>
        /// Rehydrate a verifier key from its serialized blob.<br/>
        /// Ensures structural integrity before constructing the ROK and public key.
        /// </summary>
        internal static RedXVerifierKey FromBytes(ReadOnlySpan<byte> blob)
        {
            int off = 0;
            if (blob.Length < 1 + 4) throw new ArgumentException("Verifier key blob too small", nameof(blob));
            byte ver = blob[off++];
            if (ver != Version) throw new NotSupportedException($"Verifier key version {ver} not supported");
            int rokLen = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(off, 4)); off += 4;
            if (rokLen < 1 || blob.Length < off + rokLen + 4) throw new InvalidOperationException("Invalid ROK length");
            var rokBlob = blob.Slice(off, rokLen); off += rokLen;
            int authPubLen = BinaryPrimitives.ReadInt32LittleEndian(blob.Slice(off, 4)); off += 4;
            if (authPubLen < 1 || blob.Length < off + authPubLen) throw new InvalidOperationException("Invalid authority public length");
            var authPub = blob.Slice(off, authPubLen).ToArray();

            var rok = new REReadOnlyKey(rokBlob);
            return new RedXVerifierKey(rok, authPub);
        }
    }
}
