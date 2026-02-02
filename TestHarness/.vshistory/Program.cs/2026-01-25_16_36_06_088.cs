using RedxLib;
using RedxLib;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using REAnti = RedxLib.RedX;
using REKeyAnti = RedxLib.REKey;
using RERokAnti = RedxLib.REReadOnlyKey;

Console.WriteLine("RedX test harness - size matrix for ciphertext overhead (ROK + authority proofs)\n");

// small helper to set private/internal fields for deterministic fixtures
void SetField<T>(object target, string name, T value)
{
    target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!.SetValue(target, value);
}

T GetField<T>(object target, string name)
{
    return (T)target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)!.GetValue(target)!;
}

uint ComputeH32Deterministic(ReadOnlySpan<byte> keyHash, int index, ushort nonce)
{
    Span<byte> buf = stackalloc byte[8 + 4 + 2];
    for (int i = 0; i < 8; i++) buf[i] = keyHash[i];
    BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(8, 4), index);
    BinaryPrimitives.WriteUInt16LittleEndian(buf.Slice(12, 2), nonce);

    var h = Blake3.Hasher.New();
    h.Update(buf);
    Span<byte> out4 = stackalloc byte[4];
    h.Finalize(out4);
    return MemoryMarshal.Read<uint>(out4);
}

byte[] BuildRokBlob(byte[] keyHashBytes, ushort[] nonces, uint[] h32Arr)
{
    int hashLen = keyHashBytes.Length;
    int entryCount = nonces.Length;
    int total = 4 + hashLen + entryCount * (2 + 4);
    var blob = new byte[total];
    int off = 0;

    BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(off, 4), hashLen);
    off += 4;
    keyHashBytes.CopyTo(blob.AsSpan(off, hashLen));
    off += hashLen;

    for (int i = 0; i < entryCount; i++)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(blob.AsSpan(off, 2), nonces[i]);
        off += 2;
    }
    for (int i = 0; i < entryCount; i++)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(off, 4), h32Arr[i]);
        off += 4;
    }

    return blob;
}

(REKeyAnti key, RERokAnti rok, byte[] rokBlob, byte[] keyHashBytes, ushort[] nonces) CreateDeterministicKeyAndRok()
{
    const int keyBlockSize = 1;
    int keyLength = 256 * keyBlockSize;

    var key = new REKeyAnti((byte)keyBlockSize);

    var keyBytes = new byte[keyLength];
    for (int i = 0; i < keyLength; i++)
        keyBytes[i] = (byte)(i & 0xFF);

    var rkd = new byte[keyBlockSize][];
    for (int r = 0; r < keyBlockSize; r++)
    {
        var row = new byte[256];
        for (int v = 0; v < 256; v++) row[v] = (byte)v;
        rkd[r] = row;
    }

    var keyHashBytes = new byte[64];
    {
        var b3 = Blake3.Hasher.New();
        b3.Update(keyBytes.AsSpan());
        b3.Finalize(keyHashBytes);
    }

    SetField(key, "key", keyBytes);
    SetField(key, "rkd", rkd);
    SetField(key, "keyLength", keyLength);
    SetField(key, "keyHash", new Memory<byte>(keyHashBytes));
    SetField(key, "keyBlockSize", (byte)keyBlockSize);

    var nonces = new ushort[keyLength];
    var h32Arr = new uint[keyLength];
    for (int i = 0; i < keyLength; i++)
    {
        nonces[i] = (ushort)((i * 109 + 257) & 0xFFFF);
        h32Arr[i] = ComputeH32Deterministic(keyHashBytes, i, nonces[i]);
    }

    var rokBlob = BuildRokBlob(keyHashBytes, nonces, h32Arr);
    var rok = new RERokAnti(rokBlob);

    return (key, rok, rokBlob, keyHashBytes, nonces);
}

List<int> TraceFlatIndices(ReadOnlySpan<byte> distStream, REKeyAnti key, short startLocation, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> keyHashBytes)
{
    int keyBlockSize = GetField<byte>(key, "keyBlockSize");
    int keyLength = GetField<int>(key, "keyLength");

    startLocation = (short)(startLocation % keyLength);
    int curRow = (startLocation / 256) % keyBlockSize;
    int curCol = startLocation % 256;
    int ivLen = iv.Length;

    var bx = new JumpGenerator(keyHashBytes, 1, iv);
    var indices = new List<int>(distStream.Length);

    foreach (byte dist in distStream)
    {
        ushort skip = bx.NextJump16();
        int colJump = skip & 0xFF;
        int rowJump = (skip >> 8) % keyBlockSize;
        curRow = (curRow + rowJump) % keyBlockSize;
        curCol = (curCol + colJump) & 0xFF;

        int newCol = (curCol + dist) & 0xFF;
        int flatIndex = curRow * 256 + newCol;
        indices.Add(flatIndex);

        curCol = newCol;
        curRow = (curRow + 1) % keyBlockSize;
    }

    return indices;
}

BufferStream BuildDeterministicCipher(REKeyAnti key, ReadOnlySpan<byte> plain, short startLocation, ReadOnlySpan<byte> rokLock, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> keyHashBytes, out List<int> usedFlatIndices)
{
    var ret = new BufferStream();
    ret.Write7BitInt(startLocation);
    ret.Write(rokLock.ToArray());

    var ivArr = iv.ToArray();
    byte ivLen = (byte)ivArr.Length;
    ret.Write(ivLen);

    using (var headerEnc = key.MapData(ivArr, ivLen))
        ret.Write(headerEnc);

    using var cipher = key.MapData(plain, startLocation, ivArr);
    var distBytes = cipher.AsReadOnlySpan.ToArray();
    usedFlatIndices = TraceFlatIndices(distBytes, key, startLocation, iv, keyHashBytes);

    var b3 = Blake3.Hasher.New();
    b3.Update(distBytes);
    b3.Update(iv);
    Span<byte> auth = stackalloc byte[32];
    b3.Finalize(auth);
    using (var authEnc = key.MapData(auth, ivLen, ivArr))
        ret.Write(authEnc);

    ret.Write(distBytes);
    ret.Position = 0;
    return ret;
}

byte[] BuildDeterministicAuthorityCipher(REKeyAnti key, ReadOnlySpan<byte> plain, short startLocation, ReadOnlySpan<byte> rokLock, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> authorityPrivPkcs8, out byte[] authorityPubSpki)
{
    // mimic EncryptAntiSym with fixed params
    const int AuthorityCheckpointMax = 64;
    const int ObserverStateSize = 32;
    const int AuthoritySigSize = 64;
    Span<byte> AuthorityDomain = stackalloc byte[]
    {
        (byte)'R',(byte)'E',(byte)'D',(byte)'X',(byte)'_',
        (byte)'A',(byte)'U',(byte)'T',(byte)'H',(byte)'_',
        (byte)'C',(byte)'K',(byte)'P',(byte)'T',(byte)'_',
        (byte)'V',(byte)'1'
    };

    int desired = (plain.Length + 63) / 64;
    if (desired < 1) desired = 1;
    if (desired > AuthorityCheckpointMax) desired = AuthorityCheckpointMax;
    int ckCount = desired;
    int interval = (plain.Length + ckCount - 1) / ckCount;
    if (interval < 1) interval = 1;

    byte[] ckStates = ckCount > 0 ? new byte[ckCount * ObserverStateSize] : Array.Empty<byte>();
    var ivArr = iv.ToArray();
    using var cipher = key.MapDataWithObserver(plain, startLocation, ivArr, interval, ckCount, ckStates);

    var keyHashBytes = GetField<Memory<byte>>(key, "keyHash").ToArray();
    Span<byte> msg = stackalloc byte[AuthorityDomain.Length + 32 + 4 + ObserverStateSize];
    ReadOnlySpan<byte> rKeyId32 = keyHashBytes.AsSpan(0, 32);
    byte[] sigs = ckCount > 0 ? new byte[ckCount * AuthoritySigSize] : Array.Empty<byte>();

    using (var ecdsa = ECDsa.Create())
    {
        ecdsa.ImportPkcs8PrivateKey(authorityPrivPkcs8, out _);
        authorityPubSpki = ecdsa.ExportSubjectPublicKeyInfo();

        for (int i = 0; i < ckCount; i++)
        {
            var st = ckStates.AsSpan(i * ObserverStateSize, ObserverStateSize);
            int msgLen = AuthorityDomain.Length + 32 + 4 + ObserverStateSize;
            AuthorityDomain.CopyTo(msg);
            rKeyId32.CopyTo(msg.Slice(AuthorityDomain.Length, 32));
            BinaryPrimitives.WriteInt32LittleEndian(msg.Slice(AuthorityDomain.Length + 32, 4), i);
            st.CopyTo(msg.Slice(AuthorityDomain.Length + 32 + 4, ObserverStateSize));

            var sigDest = sigs.AsSpan(i * AuthoritySigSize, AuthoritySigSize);
            if (!ecdsa.TrySignData(msg.Slice(0, msgLen), sigDest, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out int written) || written != AuthoritySigSize)
                throw new CryptographicException("authority signing failed");
        }
    }

    Span<byte> cntBuf = stackalloc byte[4];
    BinaryPrimitives.WriteInt32LittleEndian(cntBuf, ckCount);
    var rokLockArr = rokLock.ToArray();

    var ret = new BufferStream();
    ret.Write7BitInt(startLocation);
    ret.Write(rokLock.ToArray());
    using (var cntEnc = key.MapData(cntBuf, 0, rokLockArr))
        ret.Write(cntEnc);
    for (int i = 0; i < ckCount; i++)
    {
        var sig = sigs.AsSpan(i * AuthoritySigSize, AuthoritySigSize);
        using var sigEnc = key.MapData(sig, 0, rokLockArr);
        ret.Write(sigEnc);
    }

    byte ivLen = (byte)ivArr.Length;
    ret.Write(ivLen);
    using (var headerEnc = key.MapData(ivArr, ivLen))
        ret.Write(headerEnc);

    var cipherBytes = cipher.AsReadOnlySpan.ToArray();

    var b3 = Blake3.Hasher.New();
    b3.Update(cipherBytes);
    b3.Update(ivArr);
    Span<byte> auth = stackalloc byte[32];
    b3.Finalize(auth);
    using (var authEnc = key.MapData(auth, ivLen, ivArr))
        ret.Write(authEnc);

    ret.Write(cipherBytes);
    ret.Position = 0;
    return ret.ToArray();
}

void RunDeterministicRokTest()
{
    Console.WriteLine("Deterministic ROK test suite (RE AntiSym)");

    var (key, rok, rokBlob, keyHashBytes, nonces) = CreateDeterministicKeyAndRok();

    var plain = Encoding.UTF8.GetBytes("deterministic-rok-plain");
    short startLocation = 17;
    var rokLock = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
    var iv = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

    var ct = BuildDeterministicCipher(key, plain, startLocation, rokLock, iv, keyHashBytes, out var usedFlatIndices);
    var ctBytes = ct.ToArray();
    // Authority-signed ciphertext using real EncryptAntiSym with ROK-targeted headers
    using var authKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var authPriv = authKey.ExportPkcs8PrivateKey();
    var authPubKey = authKey.ExportSubjectPublicKeyInfo();
    var ctAuthStream = REAnti.EncryptAntiSym(plain, key, rok, authPriv);
    var ctAuthBytes = ctAuthStream.ToArray();

    BufferStream CaseDecrypt(string name, Func<BufferStream> fn)
    {
        BufferStream dec = null;
        Exception ex = null;
        try { dec = fn(); } catch (Exception e) { ex = e; }
        Console.WriteLine($"  [{name}] ok: {dec != null}");
        if (ex != null) Console.WriteLine($"  [{name}] exception: {ex.GetType().Name}: {ex.Message}");
        Console.WriteLine($"  [{name}] plaintext: {(dec == null ? "<null>" : Encoding.UTF8.GetString(dec.AsReadOnlySpan))}");
        return dec;
    }

    Console.WriteLine("  === baseline ===");
    CaseDecrypt("baseline", () => REAnti.Decrypt(new BufferStream(ctBytes), rok));
    Console.WriteLine($"  ciphertext (base64): {Convert.ToBase64String(ctBytes)}");
    Console.WriteLine($"  startLocation: {startLocation}");
    Console.WriteLine($"  rokLock: {BitConverter.ToString(rokLock)}");
    Console.WriteLine($"  iv: {BitConverter.ToString(iv)}");
    Console.WriteLine($"  keyHash (base64): {Convert.ToBase64String(keyHashBytes)}");
    Console.WriteLine($"  rok blob (base64): {Convert.ToBase64String(rokBlob)}");
    Console.WriteLine($"  used flat indices: {string.Join(",", usedFlatIndices)}");

    Console.WriteLine("  === tamper cases ===");

    // Tamper 1: flip keyHash[0] inside ROK blob
    {
        int tamperOffset = 4; // first byte of keyHash in blob (hashLen is 4 bytes)
        var tamperedBlob = (byte[])rokBlob.Clone();
        byte khBefore = tamperedBlob[tamperOffset];
        tamperedBlob[tamperOffset] ^= 0xFF;
        byte khAfter = tamperedBlob[tamperOffset];
        Console.WriteLine($"  [tamper-keyhash] offset={tamperOffset} before=0x{khBefore:X2} after=0x{khAfter:X2}");
        CaseDecrypt("tamper-keyhash", () => REAnti.Decrypt(new BufferStream(ctBytes), new RERokAnti(tamperedBlob)));
        Console.WriteLine($"  tampered rok blob (base64): {Convert.ToBase64String(tamperedBlob)}");
    }

    // Tamper 2: flip nonce at first used flat index
    {
        int tamperIdx = usedFlatIndices.Count > 0 ? usedFlatIndices[0] : 0;
        int nonceOffset = 4 + keyHashBytes.Length + tamperIdx * 2;
        var tamperedBlob = (byte[])rokBlob.Clone();
        ushort nonceBefore = BinaryPrimitives.ReadUInt16LittleEndian(tamperedBlob.AsSpan(nonceOffset, 2));
        tamperedBlob[nonceOffset] ^= 0xFF;
        tamperedBlob[nonceOffset + 1] ^= 0xFF;
        ushort nonceAfter = BinaryPrimitives.ReadUInt16LittleEndian(tamperedBlob.AsSpan(nonceOffset, 2));
        Console.WriteLine($"  [tamper-nonce] idx={tamperIdx} before=0x{nonceBefore:X4} after=0x{nonceAfter:X4}");
        CaseDecrypt("tamper-nonce", () => REAnti.Decrypt(new BufferStream(ctBytes), new RERokAnti(tamperedBlob)));
        Console.WriteLine($"  tampered rok blob (base64): {Convert.ToBase64String(tamperedBlob)}");
    }

    // Tamper 3: flip auth tag byte
    {
        var tamperedCt = (byte[])ctBytes.Clone();
        int authStart = ctBytes.Length - plain.Length - 32;
        tamperedCt[authStart] ^= 0xFF;
        Console.WriteLine($"  [tamper-auth] authStart={authStart}");
        CaseDecrypt("tamper-auth", () => REAnti.Decrypt(new BufferStream(tamperedCt), rok));
        Console.WriteLine($"  tampered ciphertext (base64): {Convert.ToBase64String(tamperedCt)}");
    }

    // Tamper 4: flip one distance byte
    {
        var tamperedCt = (byte[])ctBytes.Clone();
        int distStart = ctBytes.Length - plain.Length; // distance stream start
        tamperedCt[distStart] ^= 0x01;
        Console.WriteLine($"  [tamper-dist] offset={distStart}");
        CaseDecrypt("tamper-dist", () => REAnti.Decrypt(new BufferStream(tamperedCt), rok));
        Console.WriteLine($"  tampered ciphertext (base64): {Convert.ToBase64String(tamperedCt)}");
    }

    // Authority-required path
    {
    Console.WriteLine("  === authority-required ===");
    Console.WriteLine($"  auth ciphertext len: {ctAuthBytes.Length} (plain len: {plain.Length})");
    CaseDecrypt("auth-ok", () =>
    {
        var dec = REAnti.DecryptAntiSymWithAuthority(new BufferStream(ctAuthBytes), rok, authPubKey);
        if (dec != null) Console.WriteLine($"  [auth-ok] plaintext bytes: {BitConverter.ToString(dec.ToArray())}");
        return dec;
    });

    // Tamper a signature byte (first sig ciphertext byte)
    var tamperedSigCt = (byte[])ctAuthBytes.Clone();
    var probe = new BufferStream(ctAuthBytes);
        probe.Read7BitInt(); // start
        var probeRok = probe.ReadBytes(4);
        rok.UnmapData(probe, 0, probeRok, default, 4, rejectCompactHeader: true); // count
        long sigBytePos = probe.Position; // start of first sig enc bytes
        tamperedSigCt[sigBytePos] ^= 0xFF;
        CaseDecrypt("auth-tamper-sig", () => REAnti.DecryptAntiSymWithAuthority(new BufferStream(tamperedSigCt), rok, authPubKey));
        Console.WriteLine($"  tampered auth ciphertext (base64): {Convert.ToBase64String(tamperedSigCt)}");

        // Forge attempt with ROK only should fail in authority-required mode
        short fStart = 0;
        var fRokLock = new byte[] { 0x00, 0x00, 0x00, 0x00 };
        byte fIvLen = 0;
        var fDist = new byte[] { 0x01, 0x02, 0x03 };

        Span<byte> fAuth = stackalloc byte[32];
        {
            var b3 = Blake3.Hasher.New();
            b3.Update(fDist);
            b3.Finalize(fAuth);
        }

        var fKs = new byte[fAuth.Length];
        using (var xof = new Blake3XofReader(keyHashBytes, fRokLock))
            xof.ReadNext(fKs);
        var fAuthEnc = new byte[1 + fAuth.Length];
        fAuthEnc[0] = 0xFE; // compact marker (should be rejected)
        for (int i = 0; i < fAuth.Length; i++)
            fAuthEnc[1 + i] = (byte)(fAuth[i] ^ fKs[i]);

        var forged = new BufferStream();
        forged.Write7BitInt(fStart);
        forged.Write(fRokLock);
        forged.Write(fIvLen);
        forged.Write(fAuthEnc);
        forged.Write(fDist);
        forged.Position = 0;

        Console.WriteLine("  === forge-from-rok (authority-required) ===");
        CaseDecrypt("forge-from-rok-auth", () => REAnti.DecryptAntiSymWithAuthority(new BufferStream(forged.ToArray()), rok, authPubKey));
        Console.WriteLine($"  forged ciphertext (base64): {Convert.ToBase64String(forged.ToArray())}");
    }

    Console.WriteLine();
}

void RunRandomRokTest()
{
    Console.WriteLine("Random ROK test suite (RE AntiSym)");

    var key = REAnti.CreateKey();
    var rok = key.CreateReadOnlyKey();
    var plain = Encoding.UTF8.GetBytes("random-rok-plain-" + Guid.NewGuid());

    using var authKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var authPriv = authKey.ExportPkcs8PrivateKey();
    var authPubKey = authKey.ExportSubjectPublicKeyInfo();

    var ctSym = REAnti.Encrypt(plain, key);
    var ctRokLegacy = REAnti.EncryptWithAuthority(plain, key, rok, null, 96);
    var ctAuth = REAnti.EncryptAntiSym(plain, key, rok, authPriv);

    BufferStream Case(string name, BufferStream bs, Func<BufferStream> fn)
    {
        BufferStream dec = null;
        Exception ex = null;
        try { dec = fn(); } catch (Exception e) { ex = e; }
        Console.WriteLine($"  [{name}] len={bs.Length} ok={dec != null} ex={(ex == null ? "-" : ex.GetType().Name)}");
        if (dec != null) Console.WriteLine($"  [{name}] plaintext: {Encoding.UTF8.GetString(dec.ToArray())}");
        return dec;
    }

    Console.WriteLine("  symmetric decrypt");
    Case("sym", ctSym, () => REAnti.Decrypt(new BufferStream(ctSym.ToArray()), key));

    Console.WriteLine("  ROK legacy decrypt");
    Case("rok-legacy", ctRokLegacy, () => REAnti.Decrypt(new BufferStream(ctRokLegacy.ToArray()), rok));

    Console.WriteLine("  authority-required decrypt");
    Case("auth", ctAuth, () => REAnti.DecryptAntiSymWithAuthority(new BufferStream(ctAuth.ToArray()), rok, authPubKey));
    Console.WriteLine($"  auth ciphertext len: {ctAuth.Length}, plain len: {plain.Length}");
    Console.WriteLine();
}

// helper to generate mock proofs
List<byte[]> GenerateMockProofs(int count, int proofSize)
{
    var list = new List<byte[]>(count);
    for (int i = 0; i < count; i++)
    {
        var p = new byte[proofSize];
        for (int j = 0; j < proofSize; j++) p[j] = (byte)((i + j) & 0xFF);
        list.Add(p);
    }
    return list;
}

// Pretty-print header info (best-effort, does not try to parse encrypted proofs)
void PrintHeaderInfo(BufferStream bs)
{
    bs.Position = 0;
    int startLoc = bs.Read7BitInt();
    var rokLock = bs.ReadBytes(4);
    Console.WriteLine($"  startLocation: {startLoc}");
    Console.WriteLine($"  rokLock: {BitConverter.ToString(rokLock)}");
}

// Simple sample showing symmetric and ROK-protected (anti-symmetric) usage
void ShowSimpleSamples()
{
    var fullKey = REAnti.CreateKey();
    var rok = fullKey.CreateReadOnlyKey();
    var plain = Encoding.UTF8.GetBytes("abc");

    Console.WriteLine("Simple sample for plaintext 'abc':");

    // Symmetric: encrypt with full key and decrypt with full key
    var cSym = REAnti.Encrypt(plain, fullKey);
    var cSymBytes = cSym.ToArray();
    Console.WriteLine($" Symmetric ciphertext (hex): {BitConverter.ToString(cSymBytes)}");
    var decSym = REAnti.Decrypt(new BufferStream(cSymBytes), fullKey);
    Console.WriteLine($" Symmetric decrypted: {Encoding.UTF8.GetString(decSym.AsReadOnlySpan)}");

    // Anti-symmetric (ROK): encrypt (header includes rokLock) and decrypt with ROK
    var proofs = GenerateMockProofs(1, 96);
    var cRok = REAnti.EncryptWithAuthority(plain, fullKey, rok, proofs, 96);
    var cRokBytes = cRok.ToArray();
    Console.WriteLine($" ROK-protected ciphertext (hex): {BitConverter.ToString(cRokBytes)}");
    // Try decrypting the ROK-protected ciphertext with the full key (should succeed)
    var decWithFull = REAnti.Decrypt(new BufferStream(cRokBytes), fullKey);
    Console.WriteLine(decWithFull != null
        ? $" ROK-protected decrypted with full key: {Encoding.UTF8.GetString(decWithFull.AsReadOnlySpan)}"
        : " ROK-protected decrypted with full key: <null>");

    // Then try decrypting with the ROK (may return null if verification/format differs)
    var decRok = REAnti.Decrypt(new BufferStream(cRokBytes), rok);
    Console.WriteLine(decRok != null
        ? $" ROK decrypted: {Encoding.UTF8.GetString(decRok.AsReadOnlySpan)}"
        : " ROK decrypted: <null> (decrypt failed)");

    Console.WriteLine();
}

// Run a small basic sanity check
void RunSanity()
{
    var fullKey = REAnti.CreateKey();
    var rok = fullKey.CreateReadOnlyKey();
    var plain = Encoding.UTF8.GetBytes("abc");

    Console.WriteLine("Sanity check: encrypt/decrypt small payload");
    var cNo = REAnti.Encrypt(plain, fullKey);
    Console.WriteLine($"  no-auth len: {cNo.ToArray().Length}");
    PrintHeaderInfo(new BufferStream(cNo.ToArray()));
    var decRok = REAnti.Decrypt(new BufferStream(cNo.ToArray()), rok);
    Console.WriteLine($"  ROK decryption ok: {decRok != null}");
    var proofs = GenerateMockProofs(1, 96);
    var cAuth = REAnti.EncryptWithAuthority(plain, fullKey, rok, proofs, 96);
    Console.WriteLine($"  with-auth len: {cAuth.ToArray().Length}");
    PrintHeaderInfo(new BufferStream(cAuth.ToArray()));
    Console.WriteLine();
}

// Matrix test: sizes x chunkSizes x proofSizes
void RunMatrix()
{
    var fullKey = REAnti.CreateKey();
    var rok = fullKey.CreateReadOnlyKey();

    int[] plainLens = new int[] { 1, 8, 32, 128, 512, 1024, 4096, 8192, 16384 };
    int[] chunkSizes = new int[] { 1024, 4096, 16384, 32768 };
    int[] proofSizes = new int[] { 32, 64, 96, 128 };

    Console.WriteLine("CompactThreshold (implementation): 128 bytes (small-blob fast path)");
    Console.WriteLine("Columns: plainLen | chunkSize | proofSize | proofCount | lenNo | lenAuth | overhead | ratio");

    foreach (var chunk in chunkSizes)
    {
        foreach (var psize in proofSizes)
        {
            foreach (var L in plainLens)
            {
                var plain = new byte[L];
                for (int i = 0; i < L; i++) plain[i] = (byte)(i & 0xFF);

                var cNo = REAnti.Encrypt(plain, fullKey);
                int lenNo = cNo.ToArray().Length;

                int proofCount = Math.Max(1, (int)Math.Ceiling((double)L / chunk));
                var proofs = GenerateMockProofs(proofCount, psize);
                var cAuth = REAnti.EncryptWithAuthority(plain, fullKey, rok, proofs, psize);
                int lenAuth = cAuth.ToArray().Length;

                int overhead = lenAuth - lenNo;
                double ratio = lenAuth > 0 ? (double)lenAuth / Math.Max(1, L) : 0.0;

                Console.WriteLine($"{L,6} | {chunk,8} | {psize,9} | {proofCount,9} | {lenNo,6} | {lenAuth,7} | {overhead,8} | {ratio,6:F2}"); // Updated formatting
            }
        }
    }
}

RunDeterministicRokTest();
RunRandomRokTest();
