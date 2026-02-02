using RedxLib;
using RedxLib;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.IO;
using static System.Console;
using System.Text;
using System.Security.Cryptography;
using TextCopy;
using REAnti = RedxLib.RedX;
using REKeyAnti = RedxLib.REKey;
using RERokAnti = RedxLib.REReadOnlyKey;

void WriteLineColor(ConsoleColor color, string text)
{
    var old = ForegroundColor;
    ForegroundColor = color;
    WriteLine(text);
    ForegroundColor = old;
}

void WriteColor(ConsoleColor color, string text)
{
    var old = ForegroundColor;
    ForegroundColor = color;
    Write(text);
    ForegroundColor = old;
}

WriteLineColor(ConsoleColor.Cyan, "RedX test harness - size matrix for ciphertext overhead (ROK + authority proofs)\n");

// recent artifacts for copy/paste convenience
string lastSymKeyHex = null;
string lastSymCipherHex = null;
string lastSymPlainHex = null;
string lastMintHex = null;
string lastVerifierHex = null;
string lastAntiCipherHex = null;
string lastAntiPlainHex = null;

var breadcrumb = new List<string> { "Main" };
void PrintBreadcrumb() => WriteLineColor(ConsoleColor.Magenta, $"Path: {string.Join(" > ", breadcrumb)}");

bool ClipboardAvailable() => true; // TextCopy abstracts platform differences

bool TrySetClipboard(string label, string text)
{
    try
    {
        ClipboardService.SetText(text);
        Console.WriteLine($" {label} copied to clipboard.");
        return true;
    }
    catch (Exception ex)
    {
        Console.WriteLine($" Clipboard copy failed: {ex.Message}");
        return false;
    }
}

bool TryGetClipboardHex(out byte[] bytes, out string hex)
{
    bytes = null;
    hex = null;
    try
    {
        var txt = ClipboardService.GetText();
        if (string.IsNullOrWhiteSpace(txt)) return false;
        var normalized = NormalizeHex(txt);
        if (normalized == null) return false;
        bytes = normalized;
        hex = Convert.ToHexString(bytes);
        return true;
    }
    catch
    {
        return false;
    }
}

/// <summary>
/// Normalize a hex string: strip 0x prefix, remove spaces/dashes/colons, require even length; returns null on failure.<br/>
/// </summary>
byte[] NormalizeHex(string input)
{
    if (string.IsNullOrWhiteSpace(input)) return null;
    var sb = new StringBuilder(input.Length);
    int i = 0;
    var s = input.Trim();
    if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        s = s.Substring(2);
    foreach (var ch in s)
    {
        if (ch == ' ' || ch == '-' || ch == ':' || ch == '\t' || ch == '\r' || ch == '\n')
            continue;
        sb.Append(ch);
    }
    if ((sb.Length & 1) != 0) return null;
    try
    {
        return Convert.FromHexString(sb.ToString());
    }
    catch
    {
        return null;
    }
}

void CopyNow(string label, string hex)
{
    if (hex == null)
    {
        Console.WriteLine($" No {label} available to copy.");
        return;
    }
    TrySetClipboard(label, hex);
}

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

    var sw = new Stopwatch();
    var timings = new List<(string Name, double Ms)>();

    sw.Restart();
    var (key, rok, rokBlob, keyHashBytes, nonces) = CreateDeterministicKeyAndRok();
    sw.Stop();
    timings.Add(("create deterministic key+rok", sw.Elapsed.TotalMilliseconds));
    Console.WriteLine($"  [timing] create deterministic key+rok: {sw.Elapsed.TotalMilliseconds:N3} ms");

    var plain = Encoding.UTF8.GetBytes("deterministic-rok-plain");
    short startLocation = 17;
    var rokLock = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
    var iv = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

    sw.Restart();
    var ct = BuildDeterministicCipher(key, plain, startLocation, rokLock, iv, keyHashBytes, out var usedFlatIndices);
    sw.Stop();
    timings.Add(("build deterministic cipher", sw.Elapsed.TotalMilliseconds));
    Console.WriteLine($"  [timing] build deterministic cipher: {sw.Elapsed.TotalMilliseconds:N3} ms");

    var ctBytes = ct.ToArray();
    // Authority-signed ciphertext using real EncryptAntiSym with ROK-targeted headers
    using var authKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var authPriv = authKey.ExportPkcs8PrivateKey();
    var authPubKey = authKey.ExportSubjectPublicKeyInfo();

    sw.Restart();
    var ctAuthStream = REAnti.EncryptAntiSym(plain, key, rok, authPriv);
    sw.Stop();
    timings.Add(("encrypt (authority-required)", sw.Elapsed.TotalMilliseconds));
    Console.WriteLine($"  [timing] encrypt (authority-required): {sw.Elapsed.TotalMilliseconds:N3} ms");

    var ctAuthBytes = ctAuthStream.ToArray();

    BufferStream CaseDecrypt(string name, Func<BufferStream> fn)
    {
        BufferStream dec = null;
        Exception ex = null;
        sw.Restart();
        try { dec = fn(); } catch (Exception e) { ex = e; }
        sw.Stop();
        double elapsedMs = sw.Elapsed.TotalMilliseconds;
        Console.WriteLine($"  [{name}] ok: {dec != null}");
        if (ex != null) Console.WriteLine($"  [{name}] exception: {ex.GetType().Name}: {ex.Message}");
        Console.WriteLine($"  [{name}] plaintext: {(dec == null ? "<null>" : Encoding.UTF8.GetString(dec.AsReadOnlySpan))}");
        timings.Add(($"decrypt:{name}", elapsedMs));
        Console.WriteLine($"  [timing] decrypt:{name}: {elapsedMs:N3} ms");
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

    Console.WriteLine("  === timing summary ===");
    double totalMs = 0;
    foreach (var (name, ms) in timings)
    {
        totalMs += ms;
        Console.WriteLine($"  [summary] {name}: {ms:N3} ms");
    }
    Console.WriteLine($"  [summary] total recorded: {totalMs:N3} ms");

    Console.WriteLine();
}

void RunRandomRokTest()
{
    Console.WriteLine("Random ROK test suite (RE AntiSym)");

    var sw = new Stopwatch();
    var timings = new List<(string Name, double Ms)>();

    var key = REAnti.CreateKey();
    var rok = key.CreateReadOnlyKey();
    var plain = Encoding.UTF8.GetBytes("random-rok-plain-" + Guid.NewGuid());

    using var authKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var authPriv = authKey.ExportPkcs8PrivateKey();
    var authPubKey = authKey.ExportSubjectPublicKeyInfo();

    sw.Restart();
    var ctSym = REAnti.Encrypt(plain, key);
    sw.Stop();
    timings.Add(("encrypt:symmetric", sw.Elapsed.TotalMilliseconds));
    Console.WriteLine($"  [timing] encrypt:symmetric: {sw.Elapsed.TotalMilliseconds:N3} ms");

    sw.Restart();
    var ctRokLegacy = REAnti.EncryptWithAuthority(plain, key, rok, null, 96);
    sw.Stop();
    timings.Add(("encrypt:rok-legacy", sw.Elapsed.TotalMilliseconds));
    Console.WriteLine($"  [timing] encrypt:rok-legacy: {sw.Elapsed.TotalMilliseconds:N3} ms");

    sw.Restart();
    var ctAuth = REAnti.EncryptAntiSym(plain, key, rok, authPriv);
    sw.Stop();
    timings.Add(("encrypt:authority-required", sw.Elapsed.TotalMilliseconds));
    Console.WriteLine($"  [timing] encrypt:authority-required: {sw.Elapsed.TotalMilliseconds:N3} ms");

    BufferStream Case(string name, BufferStream bs, Func<BufferStream> fn)
    {
        BufferStream dec = null;
        Exception ex = null;
        sw.Restart();
        try { dec = fn(); } catch (Exception e) { ex = e; }
        sw.Stop();
        double elapsedMs = sw.Elapsed.TotalMilliseconds;
        Console.WriteLine($"  [{name}] len={bs.Length} ok={dec != null} ex={(ex == null ? "-" : ex.GetType().Name)}");
        if (dec != null) Console.WriteLine($"  [{name}] plaintext: {Encoding.UTF8.GetString(dec.ToArray())}");
        timings.Add(($"decrypt:{name}", elapsedMs));
        Console.WriteLine($"  [timing] decrypt:{name}: {elapsedMs:N3} ms");
        return dec;
    }

    Console.WriteLine("  symmetric decrypt");
    Case("sym", ctSym, () => REAnti.Decrypt(new BufferStream(ctSym.ToArray()), key));

    Console.WriteLine("  ROK legacy decrypt");
    Case("rok-legacy", ctRokLegacy, () => REAnti.Decrypt(new BufferStream(ctRokLegacy.ToArray()), rok));

    Console.WriteLine("  authority-required decrypt");
    Case("auth", ctAuth, () => REAnti.DecryptAntiSymWithAuthority(new BufferStream(ctAuth.ToArray()), rok, authPubKey));
    Console.WriteLine($"  auth ciphertext len: {ctAuth.Length}, plain len: {plain.Length}");

    Console.WriteLine("  === timing summary ===");
    double totalMs = 0;
    foreach (var (name, ms) in timings)
    {
        totalMs += ms;
        Console.WriteLine($"  [summary] {name}: {ms:N3} ms");
    }
    Console.WriteLine($"  [summary] total recorded: {totalMs:N3} ms");
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

/// <summary>
/// Build a deterministic payload of the requested byte length using a repeating UTF-8 seed.<br/>
/// Keeps output reproducible while allowing “horrible” seed content to surface edge cases.<br/>
/// </summary>
byte[] BuildPatternPayload(int length, string seed)
{
    if (string.IsNullOrEmpty(seed)) throw new ArgumentException("Seed cannot be empty", nameof(seed));
    if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
    var seedBytes = Encoding.UTF8.GetBytes(seed);
    var data = new byte[length];
    for (int i = 0; i < length; i++)
        data[i] = seedBytes[i % seedBytes.Length];
    return data;
}

/// <summary>
/// Pre-canned plaintexts (no zero-length) mixing mundane and “horrible” control/ASCII patterns.<br/>
/// Lengths target 1,31,32,33,1024,4096,16384 bytes for quick eyeball and overhead checks.<br/>
/// </summary>
List<(string Label, byte[] Payload)> BuildPresetPayloads()
{
    return new List<(string, byte[])>
    {
        ("len-1-mundane", BuildPatternPayload(1, "A")),
        ("len-31-pangramish", BuildPatternPayload(31, "sphinx-of-black-quartz-judge")),
        ("len-32-repeater", BuildPatternPayload(32, "0123456789ABCDEF")),
        ("len-33-horrible", BuildPatternPayload(33, "ctrl-\u0001\u0002\u0003-~-\u007F-x")),
        ("len-1024-mixed", BuildPatternPayload(1024, "horrible-\u0001\u0002-\u0007-.-crypto-RedX-ROK-")),
        ("len-4096-mundane", BuildPatternPayload(4096, "mundane-rows-cols-random-walk-")),
        ("len-16384-binaryish", BuildPatternPayload(16384, "bin-\u0000\u0001\u0002\u0003-\u001B-~-repeat-"))
    };
}

/// <summary>
/// Render a hex preview with length tag and optional truncation for large buffers.<br/>
/// </summary>
string HexWithLen(ReadOnlySpan<byte> data, int previewBytes = 64)
{
    int show = Math.Min(data.Length, previewBytes);
    var hex = Convert.ToHexString(data.Slice(0, show));
    var suffix = data.Length > previewBytes ? "..." : string.Empty;
    return $"[len:{data.Length}] {hex}{suffix}";
}

/// <summary>
/// Render a UTF-8 view with length tag, control char escaping, and truncation for readability.<br/>
/// </summary>
string Utf8WithLen(ReadOnlySpan<byte> data, int maxChars = 120)
{
    var raw = Encoding.UTF8.GetString(data);
    var sb = new StringBuilder();
    foreach (char ch in raw)
    {
        if (ch == '\r') sb.Append("\\r");
        else if (ch == '\n') sb.Append("\\n");
        else if (char.IsControl(ch)) sb.Append('.');
        else sb.Append(ch);

        if (sb.Length >= maxChars)
        {
            sb.Append("...");
            break;
        }
    }
    return $"[len:{data.Length}] {sb}";
}

/// <summary>
/// Prompt for non-empty input, trimming whitespace; loops until provided.<br/>
/// </summary>
string ReadRequired(string prompt)
{
    while (true)
    {
        Console.Write(prompt);
        var input = (Console.ReadLine() ?? string.Empty).Trim();
        if (!string.IsNullOrWhiteSpace(input))
            return input;
        Console.WriteLine("Please enter a value.");
    }
}

/// <summary>
/// Prompt for required input but allow cancel with 0/empty/EOF; returns null on cancel.<br/>
/// </summary>
string ReadRequiredCancelable(string prompt)
{
    while (true)
    {
        Console.Write(prompt);
        var raw = Console.ReadLine();
        if (raw == null) return null;
        var input = raw.Trim();
        if (string.IsNullOrEmpty(input)) return null; // blank = cancel
        return input;
    }
}

/// <summary>
/// Prompt for a choice among fixed options; case-insensitive; loops until valid.<br/>
/// </summary>
string ReadChoice(string prompt, params string[] allowed)
{
    while (true)
    {
        Console.Write(prompt);
        var input = (Console.ReadLine() ?? string.Empty).Trim();
        foreach (var option in allowed)
        {
            if (string.Equals(input, option, StringComparison.OrdinalIgnoreCase))
                return option;
        }
        Console.WriteLine($"Choose one of: {string.Join("/", allowed)}");
    }
}

/// <summary>
/// Prompt for a single keypress choice (no Enter required); case-insensitive match to allowed options.<br/>
/// ESC always returns "ESC" so callers can treat it as back/cancel even if not listed in allowed.<br/>
/// Echoes the pressed key for feedback; retries on invalid input.<br/>
/// </summary>
string ReadChoiceKey(string prompt, params string[] allowed)
{
    while (true)
    {
        Console.Write(prompt);
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Escape)
        {
            Console.WriteLine("[ESC]");
            return "ESC";
        }
        var s = key.KeyChar.ToString();
        Console.WriteLine(s);
        foreach (var option in allowed)
        {
            if (string.Equals(s, option, StringComparison.OrdinalIgnoreCase))
                return option;
        }
        Console.WriteLine($"Choose one of: {string.Join("/", allowed)} or ESC");
    }
}

/// <summary>
/// Prompt for hex input and return decoded bytes; loops until valid hex is provided.<br/>
/// </summary>
byte[] ReadHexBytes(string prompt)
{
    while (true)
    {
        if (TryGetClipboardHex(out var cbBytes, out var cbHex))
        {
            Console.WriteLine($" Clipboard hex detected [{cbBytes.Length} bytes]; press Enter to use it, or type anything else to enter manually.");
            var line = Console.ReadLine();
            if (string.IsNullOrEmpty(line))
                return cbBytes;
        }

        var input = ReadRequiredCancelable(prompt + " (blank to cancel): ");
        if (input == null) return null;
        var normalized = NormalizeHex(input);
        if (normalized == null)
        {
            Console.WriteLine("Invalid hex. Please try again (remove separators, ensure even length).");
            continue;
        }
        return normalized;
    }
}

/// <summary>
/// Prompt for payload bytes as UTF-8 text or hex; caller supplies context label (e.g. plaintext/ciphertext).<br/>
/// </summary>
byte[]? PromptPayloadBytes(string label)
{
    Console.WriteLine($"{label}: choose input type");
    Console.WriteLine("  A) UTF-8 text");
    Console.WriteLine("  B) Hex");
    bool cbHexAvailable = TryGetClipboardHex(out var cbBytes, out var cbHex);
    if (cbHexAvailable) Console.WriteLine("  C) Hex from clipboard");
    Console.WriteLine("  X) Back (ESC)");
    var allowed = cbHexAvailable ? new[] { "A", "B", "C", "X" } : new[] { "A", "B", "X" };
    var choice = ReadChoiceKey($"Select ({string.Join("/", allowed)} or ESC): ", allowed);
    if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return null;
    if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
    {
        var text = ReadRequiredCancelable($"Enter {label} (UTF-8, blank to cancel): ");
        return text == null ? null : Encoding.UTF8.GetBytes(text);
    }
    if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase) && cbHexAvailable)
    {
        Console.WriteLine($" Using clipboard hex [{cbBytes.Length} bytes].");
        return cbBytes;
    }

    return ReadHexBytes($"Enter {label} as hex: ");
}

/// <summary>
/// Display serialized key blob hex and inferred block size for the symmetric key.<br/>
/// </summary>
void PrintSymmetricKeyInfo(REKey key)
{
    var blob = key.ToBytes();
    int keyLen = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(1, 4));
    int blockSize = keyLen / 256;
    Console.WriteLine($" Symmetric key blockSize: {blockSize}");
    WriteLineColor(ConsoleColor.Yellow, $" Symmetric key blob (hex): {HexWithLen(blob)}");
    lastSymKeyHex = Convert.ToHexString(blob);
}

void ShowCurrentSymmetricKey()
{
    if (lastSymKeyHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No symmetric key selected.");
        return;
    }
    int lenBytes = lastSymKeyHex.Length / 2;
    int blockSize = lenBytes / 256;
    string preview = lastSymKeyHex.Length > 80 ? lastSymKeyHex[..80] + "..." : lastSymKeyHex;
    WriteLineColor(ConsoleColor.Yellow, $" Current symmetric key: [len:{lenBytes} bytes, blockSize:{blockSize}] {preview}");
}

void ShowCurrentSymmetricPlain()
{
    if (lastSymPlainHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No symmetric plaintext recorded.");
        return;
    }
    var bytes = Convert.FromHexString(lastSymPlainHex);
    WriteLineColor(ConsoleColor.Yellow, $" Current symmetric plaintext hex: {HexWithLen(bytes)}");
    WriteLineColor(ConsoleColor.White, $" Current symmetric plaintext utf8: {Utf8WithLen(bytes)}");
}

void ShowCurrentSymmetricCipher()
{
    if (lastSymCipherHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No symmetric ciphertext recorded.");
        return;
    }
    var bytes = Convert.FromHexString(lastSymCipherHex);
    WriteLineColor(ConsoleColor.Yellow, $" Current symmetric ciphertext hex: {HexWithLen(bytes)}");
}

void CopyCurrentSymmetricKey() => CopyNow("symmetric key", lastSymKeyHex);
void CopyCurrentSymmetricPlain() => CopyNow("symmetric plaintext", lastSymPlainHex);
void CopyCurrentSymmetricCipher() => CopyNow("symmetric ciphertext", lastSymCipherHex);

/// <summary>
/// Choose or import a symmetric key (new default/custom block size, or hex import).<br/>
/// </summary>
REKey ResolveSymmetricKey()
{
    breadcrumb = new List<string> { "Main", "Symmetric", "Key Selection" };
    while (true)
    {
        PrintBreadcrumb();
        WriteLineColor(ConsoleColor.Cyan, "Symmetric key options:");
        Console.WriteLine("  A) New key (default blockSize=8)");
        Console.WriteLine("  B) New key (custom blockSize)");
        Console.WriteLine("  C) Import key from hex (REKey.ToBytes)");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A/B/C/X or ESC): ", "A", "B", "C", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return null;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
        {
            var key = REAnti.CreateKey();
            PrintSymmetricKeyInfo(key);
            return key;
        }
        if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            var blkStr = ReadRequiredCancelable("Enter block size (rows, 1-255, blank to cancel): ");
            if (blkStr == null) continue;
            if (byte.TryParse(blkStr, out var blk) && blk > 0)
            {
                var key = REAnti.CreateKey(blk);
                PrintSymmetricKeyInfo(key);
                return key;
            }
            WriteLineColor(ConsoleColor.Red, "Invalid block size.");
        }
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = ReadHexBytes("Enter key blob hex: ");
            if (bytes == null) continue;
            try
            {
                var key = REAnti.CreateKeyFromBytes(bytes);
                PrintSymmetricKeyInfo(key);
                return key;
            }
            catch (Exception ex)
            {
                WriteLineColor(ConsoleColor.Red, $"Failed to import key: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }
}

/// <summary>
/// Run pre-canned symmetric encrypt/decrypt pairs with the current key and print before/after info.<br/>
/// </summary>
void RunSymmetricPreset(REKey key, bool includeAuth)
{
    WriteLineColor(ConsoleColor.Cyan, "=== Symmetric pre-canned cases ===");
    foreach (var (label, plain) in BuildPresetPayloads())
    {
        var ct = REAnti.Encrypt(plain, key, includeAuth);
        var ctBytes = ct.ToArray();
        var dec = REAnti.Decrypt(new BufferStream(ctBytes), key, includeAuth);
        var decBytes = dec?.ToArray() ?? Array.Empty<byte>();
        bool match = dec != null && plain.AsSpan().SequenceEqual(decBytes);
        lastSymCipherHex = Convert.ToHexString(ctBytes);
        lastSymPlainHex = Convert.ToHexString(plain);
        Console.WriteLine($"[{label}] plaintext utf8: {Utf8WithLen(plain)}");
        Console.WriteLine($"[{label}] plaintext hex:  {HexWithLen(plain)}");
        Console.WriteLine($"[{label}] ciphertext:    {HexWithLen(ctBytes)} (overhead:{ctBytes.Length - plain.Length})");
        Console.WriteLine($"[{label}] decrypted:     {Utf8WithLen(decBytes)}");
        WriteLineColor(match ? ConsoleColor.Green : ConsoleColor.Red,
            $"[{label}] Plaintext Decrypt Matches Original: {match}");
        Console.WriteLine();
    }
}

/// <summary>
/// Interactive symmetric encrypt with the current key; prints plaintext/ciphertext and overhead.<br/>
/// </summary>
void SymmetricEncryptInteractive(REKey key, bool includeAuth)
{
    var plain = PromptPayloadBytes("plaintext");
    if (plain == null) return;
    // new plaintext invalidates prior ciphertext
    lastSymCipherHex = null;
    var ct = REAnti.Encrypt(plain, key, includeAuth);
    var ctBytes = ct.ToArray();
    lastSymCipherHex = Convert.ToHexString(ctBytes);
    lastSymPlainHex = Convert.ToHexString(plain);
    var dec = REAnti.Decrypt(new BufferStream(ctBytes), key, includeAuth);
    var decBytes = dec?.ToArray() ?? Array.Empty<byte>();
    bool match = dec != null && plain.AsSpan().SequenceEqual(decBytes);
    WriteLineColor(ConsoleColor.Cyan, "=== Symmetric encrypt ===");
    Console.WriteLine($" plaintext utf8: {Utf8WithLen(plain)}");
    Console.WriteLine($" plaintext hex:  {HexWithLen(plain)}");
    Console.WriteLine($" ciphertext:     {HexWithLen(ctBytes)} (overhead:{ctBytes.Length - plain.Length})");
    WriteLineColor(match ? ConsoleColor.Green : ConsoleColor.Red, $" Plaintext Decrypt Matches Original: {match}");
}

/// <summary>
/// Interactive symmetric decrypt with the current key; prints ciphertext and recovered plaintext.<br/>
/// </summary>
void SymmetricDecryptInteractive(REKey key, bool expectAuth)
{
    var ctBytes = PromptPayloadBytes("ciphertext (hex preferred)");
    if (ctBytes == null) return;
    WriteLineColor(ConsoleColor.Cyan, "=== Symmetric decrypt ===");
    Console.WriteLine($" ciphertext: {HexWithLen(ctBytes)}");
    lastSymCipherHex = Convert.ToHexString(ctBytes);
    BufferStream dec = null;
    try
    {
        dec = REAnti.Decrypt(new BufferStream(ctBytes), key, expectAuth);
    }
    catch (Exception ex)
    {
        WriteLineColor(ConsoleColor.Red, $" decrypt exception: {ex.GetType().Name}: {ex.Message}");
    }

    if (dec == null)
    {
        WriteLineColor(ConsoleColor.Red, " decrypt failed (null result)");
        return;
    }

    var plain = dec.ToArray();
    lastSymPlainHex = Convert.ToHexString(plain);
    Console.WriteLine($" plaintext utf8: {Utf8WithLen(plain)}");
    Console.WriteLine($" plaintext hex:  {HexWithLen(plain)}");
    WriteLineColor(ConsoleColor.DarkGray, " Plaintext Decrypt Matches Original: n/a");
}

/// <summary>
/// Symmetric menu: choose key, run pre-canned cases, encrypt, decrypt.<br/>
/// </summary>
bool HasSymKey() => lastSymKeyHex != null;
bool HasSymPlain() => lastSymPlainHex != null;
bool HasSymCipher() => lastSymCipherHex != null;

bool HasAntiMint() => lastMintHex != null;
bool HasAntiVerifier() => lastVerifierHex != null;
bool HasAntiPlain() => lastAntiPlainHex != null;
bool HasAntiCipher() => lastAntiCipherHex != null;

void RunSymmetricMenu()
{
    breadcrumb = new List<string> { "Main", "Symmetric" };
    bool includeAuthSym = true;
    var key = ResolveSymmetricKey();
    if (key == null) return;
    while (true)
    {
        PrintBreadcrumb();
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Symmetric menu:");
        Console.WriteLine($"  A) Pre-canned demo (auth:{(includeAuthSym ? "on" : "off")})");
        Console.WriteLine("  B) Encrypt plaintext");
        Console.WriteLine("  C) Decrypt ciphertext");
        Console.WriteLine("  D) Toggle auth tag on/off");
        Console.WriteLine($"  E) Show current key {(HasSymKey() ? "[set]" : "[none]")}");
        Console.WriteLine($"  F) Show current plaintext {(HasSymPlain() ? "[set]" : "[none]")}");
        Console.WriteLine($"  G) Show current ciphertext {(HasSymCipher() ? "[set]" : "[none]")}");
        Console.WriteLine($"  H) Copy current key {(HasSymKey() ? "[set]" : "[none]")}");
        Console.WriteLine($"  I) Copy current plaintext {(HasSymPlain() ? "[set]" : "[none]")}");
        Console.WriteLine($"  J) Copy current ciphertext {(HasSymCipher() ? "[set]" : "[none]")}");
        Console.WriteLine("  K) Change key");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A-K/X or ESC): ", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) RunSymmetricPreset(key, includeAuthSym);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) SymmetricEncryptInteractive(key, includeAuthSym);
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase)) SymmetricDecryptInteractive(key, includeAuthSym);
        else if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase)) includeAuthSym = !includeAuthSym;
        else if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase)) ShowCurrentSymmetricKey();
        else if (string.Equals(choice, "F", StringComparison.OrdinalIgnoreCase)) ShowCurrentSymmetricPlain();
        else if (string.Equals(choice, "G", StringComparison.OrdinalIgnoreCase)) ShowCurrentSymmetricCipher();
        else if (string.Equals(choice, "H", StringComparison.OrdinalIgnoreCase)) CopyCurrentSymmetricKey();
        else if (string.Equals(choice, "I", StringComparison.OrdinalIgnoreCase)) CopyCurrentSymmetricPlain();
        else if (string.Equals(choice, "J", StringComparison.OrdinalIgnoreCase)) CopyCurrentSymmetricCipher();
        else if (string.Equals(choice, "K", StringComparison.OrdinalIgnoreCase))
        {
            var newKey = ResolveSymmetricKey();
            if (newKey != null) key = newKey;
        }
    }
}

/// <summary>
/// Print minting/verifier blobs for anti-symmetric mode with len-tagged hex.<br/>
/// </summary>
void PrintMintingInfo(RedXMintingKey minting, RedXVerifierKey verifier)
{
    var mintBlob = minting.ToBytes();
    var verBlob = verifier.ToBytes();
    Console.WriteLine($" Minting key blob (hex): {HexWithLen(mintBlob)}");
    Console.WriteLine($" Verifier key blob (hex): {HexWithLen(verBlob)}");
    lastMintHex = Convert.ToHexString(mintBlob);
    lastVerifierHex = Convert.ToHexString(verBlob);
}

void ShowCurrentAntiKeys()
{
    if (lastMintHex == null && lastVerifierHex == null)
    {
        Console.WriteLine(" No anti-symmetric keys selected.");
        return;
    }
    if (lastMintHex != null)
    {
        int lenBytes = lastMintHex.Length / 2;
        string preview = lastMintHex.Length > 80 ? lastMintHex[..80] + "..." : lastMintHex;
        WriteLineColor(ConsoleColor.Yellow, $" Minting key: [len:{lenBytes}] {preview}");
    }
    if (lastVerifierHex != null)
    {
        int lenBytes = lastVerifierHex.Length / 2;
        string preview = lastVerifierHex.Length > 80 ? lastVerifierHex[..80] + "..." : lastVerifierHex;
        WriteLineColor(ConsoleColor.Yellow, $" Verifier key: [len:{lenBytes}] {preview}");
    }
}

void ShowCurrentAntiPlain()
{
    if (lastAntiPlainHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No anti-symmetric plaintext recorded.");
        return;
    }
    var bytes = Convert.FromHexString(lastAntiPlainHex);
    WriteLineColor(ConsoleColor.Yellow, $" Current anti-symmetric plaintext hex: {HexWithLen(bytes)}");
    WriteLineColor(ConsoleColor.White, $" Current anti-symmetric plaintext utf8: {Utf8WithLen(bytes)}");
}

void ShowCurrentAntiCipher()
{
    if (lastAntiCipherHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No anti-symmetric ciphertext recorded.");
        return;
    }
    var bytes = Convert.FromHexString(lastAntiCipherHex);
    WriteLineColor(ConsoleColor.Yellow, $" Current anti-symmetric ciphertext hex: {HexWithLen(bytes)}");
}

void CopyCurrentMintingKey() => CopyNow("minting key", lastMintHex);
void CopyCurrentVerifierKey() => CopyNow("verifier key", lastVerifierHex);
void CopyCurrentAntiPlain() => CopyNow("anti-symmetric plaintext", lastAntiPlainHex);
void CopyCurrentAntiCipher() => CopyNow("anti-symmetric ciphertext", lastAntiCipherHex);

/// <summary>
/// Prompt for a minting/verifier selection: new pair, import minting hex (derives verifier), or import verifier hex.<br/>
/// </summary>
void SelectAntiSymKeys(ref RedXMintingKey minting, ref RedXVerifierKey verifier)
{
    while (true)
    {
        WriteLineColor(ConsoleColor.Cyan, "Anti-symmetric key options:");
        Console.WriteLine($"  A) New minting/verifier pair");
        Console.WriteLine($"  B) Import minting key from hex (derives verifier)");
        Console.WriteLine($"  C) Import verifier key from hex");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A/B/C/X or ESC): ", "A", "B", "C", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
        {
            var pair = REAnti.CreateAntiSymmetricKeyPair();
            minting = pair.minting;
            verifier = pair.verifier;
            PrintMintingInfo(minting, verifier);
            lastMintHex = Convert.ToHexString(minting.ToBytes());
            lastVerifierHex = Convert.ToHexString(verifier.ToBytes());
            return;
        }
        if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            var blob = ReadHexBytes("Enter minting key blob (hex): ");
            if (blob == null) continue;
            try
            {
                minting = REAnti.CreateMintingKey(blob);
                verifier = minting.CreateVerifierKey();
                PrintMintingInfo(minting, verifier);
                lastMintHex = Convert.ToHexString(minting.ToBytes());
                lastVerifierHex = Convert.ToHexString(verifier.ToBytes());
                return;
            }
            catch (Exception ex)
            {
                WriteLineColor(ConsoleColor.Red, $"Failed to import minting key: {ex.GetType().Name}: {ex.Message}");
            }
        }
        if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase))
        {
            var blob = ReadHexBytes("Enter verifier key blob (hex): ");
            if (blob == null) continue;
            try
            {
                verifier = REAnti.CreateVerifierKey(blob);
                WriteLineColor(ConsoleColor.Yellow, $" Verifier key blob (hex): {HexWithLen(blob)}");
                if (minting != null)
                    PrintMintingInfo(minting, verifier);
                lastVerifierHex = Convert.ToHexString(verifier.ToBytes());
                return;
            }
            catch (Exception ex)
            {
                WriteLineColor(ConsoleColor.Red, $"Failed to import verifier key: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }
}

/// <summary>
/// Run pre-canned anti-symmetric mint/verify pairs with before/after metrics.<br/>
/// </summary>
void RunAntiSymPreset(RedXMintingKey minting, RedXVerifierKey verifier, bool includeAuth)
{
    WriteLineColor(ConsoleColor.Cyan, "=== Anti-symmetric pre-canned cases ===");
    foreach (var (label, plain) in BuildPresetPayloads())
    {
        var ct = REAnti.EncryptAntiSym(plain, minting, includeAuth: includeAuth);
        var ctBytes = ct.ToArray();
        BufferStream dec = null;
        try
        {
            dec = REAnti.DecryptAntiSymWithAuthority(new BufferStream(ctBytes), verifier, expectAuth: includeAuth);
        }
        catch (InvalidDataException ex)
        {
            Console.WriteLine($"[{label}] decrypt error: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{label}] decrypt exception: {ex.GetType().Name}: {ex.Message}");
        }
        var decBytes = dec?.ToArray() ?? Array.Empty<byte>();
        bool match = dec != null && plain.AsSpan().SequenceEqual(decBytes);
        lastAntiCipherHex = Convert.ToHexString(ctBytes);
        lastAntiPlainHex = Convert.ToHexString(plain);

        Console.WriteLine($"[{label}] plaintext utf8: {Utf8WithLen(plain)}");
        Console.WriteLine($"[{label}] plaintext hex:  {HexWithLen(plain)}");
        Console.WriteLine($"[{label}] ciphertext:     {HexWithLen(ctBytes)} (overhead:{ctBytes.Length - plain.Length})");
        Console.WriteLine($"[{label}] decrypted:      {Utf8WithLen(decBytes)}");
        WriteLineColor(match ? ConsoleColor.Green : ConsoleColor.Red,
            $"[{label}] Plaintext Decrypt Matches Original: {match}");
        Console.WriteLine();
    }
}

/// <summary>
/// Interactive anti-symmetric mint (encrypt) with the current minting key; prints blobs and overhead.<br/>
/// </summary>
void AntiSymMintInteractive(RedXMintingKey minting, RedXVerifierKey verifier, bool includeAuth)
{
    var plain = PromptPayloadBytes("plaintext");
    if (plain == null) return;
    // new plaintext invalidates prior ciphertext snapshot
    lastAntiCipherHex = null;
    var ct = REAnti.EncryptAntiSym(plain, minting, includeAuth: includeAuth);
    var ctBytes = ct.ToArray();
    lastAntiCipherHex = Convert.ToHexString(ctBytes);
    lastAntiPlainHex = Convert.ToHexString(plain);
    BufferStream dec = null;
    try
    {
        dec = REAnti.DecryptAntiSymWithAuthority(new BufferStream(ctBytes), verifier, expectAuth: includeAuth);
    }
    catch (InvalidDataException ex)
    {
        Console.WriteLine($" verify error: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($" verify exception: {ex.GetType().Name}: {ex.Message}");
    }
    var decBytes = dec?.ToArray() ?? Array.Empty<byte>();
    bool match = dec != null && plain.AsSpan().SequenceEqual(decBytes);
    WriteLineColor(ConsoleColor.Cyan, "=== Anti-symmetric mint (encrypt) ===");
    PrintMintingInfo(minting, verifier);
    Console.WriteLine($" plaintext utf8: {Utf8WithLen(plain)}");
    Console.WriteLine($" plaintext hex:  {HexWithLen(plain)}");
    Console.WriteLine($" ciphertext:     {HexWithLen(ctBytes)} (overhead:{ctBytes.Length - plain.Length})");
    WriteLineColor(match ? ConsoleColor.Green : ConsoleColor.Red, $" Plaintext Decrypt Matches Original: {match}");
}

/// <summary>
/// Interactive anti-symmetric verify/decrypt with the current verifier key.<br/>
/// </summary>
void AntiSymVerifyInteractive(RedXVerifierKey verifier, bool expectAuth)
{
    var ctBytes = PromptPayloadBytes("ciphertext (hex preferred)");
    if (ctBytes == null) return;
    WriteLineColor(ConsoleColor.Cyan, "=== Anti-symmetric verify ===");
    Console.WriteLine($" ciphertext: {HexWithLen(ctBytes)}");
    lastAntiCipherHex = Convert.ToHexString(ctBytes);
    BufferStream dec = null;
    try
    {
        dec = REAnti.DecryptAntiSymWithAuthority(new BufferStream(ctBytes), verifier, expectAuth: expectAuth);
    }
    catch (InvalidDataException ex)
    {
        Console.WriteLine($" verify error: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($" verify exception: {ex.GetType().Name}: {ex.Message}");
    }

    if (dec == null)
    {
        WriteLineColor(ConsoleColor.Red, " verify failed (null result)");
        return;
    }

    var plain = dec.ToArray();
    lastAntiPlainHex = Convert.ToHexString(plain);
    Console.WriteLine($" plaintext utf8: {Utf8WithLen(plain)}");
    Console.WriteLine($" plaintext hex:  {HexWithLen(plain)}");
    WriteLineColor(ConsoleColor.DarkGray, " Plaintext Decrypt Matches Original: n/a");
}

/// <summary>
/// Anti-symmetric menu: select keys, pre-canned demo, mint, verify.<br/>
/// </summary>
void RunAntiSymMenu()
{
    RedXMintingKey minting = null;
    RedXVerifierKey verifier = null;
    bool includeAuthAnti = true;
    SelectAntiSymKeys(ref minting, ref verifier);

    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Anti-symmetric menu (mint/verify):");
        Console.WriteLine($"  A) Pre-canned demo (auth:{(includeAuthAnti ? "on" : "off")})");
        Console.WriteLine("  B) Mint (encrypt) plaintext");
        Console.WriteLine("  C) Verify (decrypt) ciphertext");
        Console.WriteLine("  D) Toggle auth tag on/off");
        Console.WriteLine($"  E) Show current keys {(HasAntiMint() || HasAntiVerifier() ? "[set]" : "[none]")}");
        Console.WriteLine($"  F) Show current plaintext {(HasAntiPlain() ? "[set]" : "[none]")}");
        Console.WriteLine($"  G) Show current ciphertext {(HasAntiCipher() ? "[set]" : "[none]")}");
        Console.WriteLine($"  H) Copy minting key {(HasAntiMint() ? "[set]" : "[none]")}");
        Console.WriteLine($"  I) Copy verifier key {(HasAntiVerifier() ? "[set]" : "[none]")}");
        Console.WriteLine($"  J) Copy current plaintext {(HasAntiPlain() ? "[set]" : "[none]")}");
        Console.WriteLine($"  K) Copy current ciphertext {(HasAntiCipher() ? "[set]" : "[none]")}");
        Console.WriteLine("  L) Change keys");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A-L/X or ESC): ", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase))
        {
            includeAuthAnti = !includeAuthAnti;
            continue;
        }
        if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase)) { ShowCurrentAntiKeys(); continue; }
        if (string.Equals(choice, "F", StringComparison.OrdinalIgnoreCase)) { ShowCurrentAntiPlain(); continue; }
        if (string.Equals(choice, "G", StringComparison.OrdinalIgnoreCase)) { ShowCurrentAntiCipher(); continue; }
        if (string.Equals(choice, "H", StringComparison.OrdinalIgnoreCase)) { CopyCurrentMintingKey(); continue; }
        if (string.Equals(choice, "I", StringComparison.OrdinalIgnoreCase)) { CopyCurrentVerifierKey(); continue; }
        if (string.Equals(choice, "J", StringComparison.OrdinalIgnoreCase)) { CopyCurrentAntiPlain(); continue; }
        if (string.Equals(choice, "K", StringComparison.OrdinalIgnoreCase)) { CopyCurrentAntiCipher(); continue; }
        if (string.Equals(choice, "L", StringComparison.OrdinalIgnoreCase)) { SelectAntiSymKeys(ref minting, ref verifier); continue; }

        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
        {
            if (minting == null || verifier == null)
            {
                WriteLineColor(ConsoleColor.Red, "Pre-canned demo needs both minting and verifier keys (set via key options L).");
                continue;
            }
            RunAntiSymPreset(minting, verifier, includeAuthAnti);
        }
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            if (minting == null)
            {
                WriteLineColor(ConsoleColor.Red, "Minting requires a minting key (set via key options L).");
                continue;
            }
            verifier ??= minting.CreateVerifierKey();
            AntiSymMintInteractive(minting, verifier, includeAuthAnti);
        }
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase))
        {
            if (verifier == null)
            {
                WriteLineColor(ConsoleColor.Red, "Verification requires a verifier key (set via key options L).");
                continue;
            }
            AntiSymVerifyInteractive(verifier, includeAuthAnti);
        }
    }
}

/// <summary>
/// Entry menu for the RedX primer harness; choose symmetric or anti-symmetric flows.<br/>
/// </summary>
void RunPrimerMenu()
{
    WriteLineColor(ConsoleColor.Cyan, "RedX primer harness (developer/cryptographer friendly)");
    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Main menu:");
        Console.WriteLine("  S) Symmetric (encrypt/decrypt)");
        Console.WriteLine("  A) Anti-symmetric (mint/verify)");
        Console.WriteLine("  X) Exit");
        var choice = ReadChoiceKey("Select (S/A/X or ESC): ", "S", "A", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "S", StringComparison.OrdinalIgnoreCase)) RunSymmetricMenu();
        else if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) RunAntiSymMenu();
    }
}

RunPrimerMenu();
// Legacy deterministic/debug runs retained for reference:
//RunDeterministicRokTest();
//RunRandomRokTest();
