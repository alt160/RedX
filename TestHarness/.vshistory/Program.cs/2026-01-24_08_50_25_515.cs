using RedxLib;
using System;
using System.Diagnostics;
using System.Text;
using System.Collections.Generic;

Console.WriteLine("RedX test harness - size matrix for ciphertext overhead (ROK + authority proofs)\n");

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

// Run a small basic sanity check
void RunSanity()
{
    var fullKey = RedX.CreateKey();
    var rok = fullKey.CreateReadOnlyKey();
    var plain = Encoding.UTF8.GetBytes("abc");

    Console.WriteLine("Sanity check: encrypt/decrypt small payload");
    var cNo = RedX.Encrypt(plain, fullKey);
    Console.WriteLine($"  no-auth len: {cNo.ToArray().Length}");
    PrintHeaderInfo(new BufferStream(cNo.ToArray()));
    var decRok = RedX.Decrypt(new BufferStream(cNo.ToArray()), rok);
    Console.WriteLine($"  ROK decryption ok: {decRok != null}");
    var proofs = GenerateMockProofs(1, 96);
    var cAuth = RedX.EncryptWithAuthority(plain, fullKey, rok, proofs, 96);
    Console.WriteLine($"  with-auth len: {cAuth.ToArray().Length}");
    PrintHeaderInfo(new BufferStream(cAuth.ToArray()));
    Console.WriteLine();
}

// Matrix test: sizes x chunkSizes x proofSizes
void RunMatrix()
{
    var fullKey = RedX.CreateKey();
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

                var cNo = RedX.Encrypt(plain, fullKey);
                int lenNo = cNo.ToArray().Length;

                int proofCount = Math.Max(1, (int)Math.Ceiling((double)L / chunk));
                var proofs = GenerateMockProofs(proofCount, psize);
                var cAuth = RedX.EncryptWithAuthority(plain, fullKey, rok, proofs, psize);
                int lenAuth = cAuth.ToArray().Length;

                int overhead = lenAuth - lenNo;
                double ratio = lenAuth > 0 ? (double)lenAuth / Math.Max(1, L) : 0.0;

                Console.WriteLine($"{L,6} | {chunk,8} | {psize,9} | {proofCount,9} | {lenNo,6} | {lenAuth,7} | {overhead,8} | {ratio,6:F2}"); // Updated formatting
            }
        }
    }
}

RunSanity();
RunMatrix();

Console.WriteLine("\nMatrix run completed.");

// ---- Authority validation tests (final summary) ----
var fullKey = RedX.CreateKey();
var rok = fullKey.CreateReadOnlyKey();
var plainSample = Encoding.UTF8.GetBytes("abc");

int proofSize = 96;
var proof = new byte[proofSize];
for (int i = 0; i < proofSize; i++) proof[i] = (byte)(i & 0xFF);
var proofs = new List<byte[]>() { proof };

var cWith = RedX.EncryptWithAuthority(plainSample, fullKey, rok, proofs, proofSize);
var cb2 = cWith.ToArray();

// Decrypt and verify
var dec = RedX.Decrypt(new BufferStream(cb2), rok);
bool decOk = dec != null && Encoding.UTF8.GetString(dec.AsReadOnlySpan) == "abc";
var verifier = new MockVrfVerifier(proof);
bool verified = RedX.VerifyAuthority(new BufferStream(cb2), rok, ReadOnlySpan<byte>.Empty, verifier, proofSize, 4096);

var wrongProof = new byte[proofSize]; wrongProof[0] = 0xFF;
var badVerifier = new MockVrfVerifier(wrongProof);
bool verifiedBad = RedX.VerifyAuthority(new BufferStream(cb2), rok, ReadOnlySpan<byte>.Empty, badVerifier, proofSize, 4096);

// Ensure encrypted-proof bytes do NOT validate if submitted directly
bool encProofAccepted = false;
try
{
    var stream = new BufferStream(cb2);
    stream.Position = 0;
    stream.Read7BitInt();
    var rlock = stream.ReadBytes(4);
    long posAfterHeader = stream.Position;

    var probe = new BufferStream(cb2);
    probe.Position = posAfterHeader;
    var cntPlain = rok.UnmapData(probe, (short)0, rlock, default, 4);
    long cntEncLen = probe.Position - posAfterHeader;
    long posProof = posAfterHeader + cntEncLen;

    var probe2 = new BufferStream(cb2);
    probe2.Position = posProof;
    var pPlain = rok.UnmapData(probe2, (short)0, rlock, default, proofSize);
    long pEncLen = probe2.Position - posProof;

    var encRaw = new byte[pEncLen];
    Array.Copy(cb2, (int)posProof, encRaw, 0, (int)pEncLen);

    encProofAccepted = verifier.Verify(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, encRaw);
}
catch
{
    encProofAccepted = false;
}

Console.WriteLine($"\nAuthority tests: decrypt ok={decOk}, verified={verified}, verifiedBad={verifiedBad}, encProofAccepted={encProofAccepted}");

bool allOk = decOk && verified && !verifiedBad && !encProofAccepted;
Console.WriteLine(allOk ? "All tests passed as expected." : "Some tests failed — inspect output above.");
return;

// simple mock VRF verifier that accepts a specific proof blob
class MockVrfVerifier : IVrfVerifier
{
    private readonly ReadOnlyMemory<byte> _expectedProof;
    public MockVrfVerifier(ReadOnlyMemory<byte> expectedProof)
    {
        _expectedProof = expectedProof;
    }

    public bool Verify(ReadOnlySpan<byte> vrfPublicKey, ReadOnlySpan<byte> transcriptTi, ReadOnlySpan<byte> proofBlob)
    {
        return proofBlob.SequenceEqual(_expectedProof.Span);
    }
}
