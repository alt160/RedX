using RobinsonEncryptionLib;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


var test = RandomNumberGenerator.GetBytes(16);

var testList = new List<byte[]>();

for (int i = 0; i < 4; i++)
{
    testList.Add(RandomNumberGenerator.GetBytes(4));
}

var folded = XorFoldingCodec.Encode(testList);

var unfolded = XorFoldingCodec.Decode(folded);



REKey? k1 = null;

var sigK = CodeBasedSignature.CbeSigner.GenerateRandomKey(2);

var msg = System.Text.Encoding.UTF8.GetBytes("hello");

var cbe=new CodeBasedSignature.CbeSigner(sigK );
var sig = cbe.Sign(msg);
var sig2 = CodeBasedSignature.CbeSigner.Verify(msg, sig,sigK,8);



//var testInput = "Chosen-ciphertext attack (IND-CCA2)\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nBrute-force attack\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nFrequency analysis\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nStatistical analysis (e.g., entropy)\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nDifferential cryptanalysis\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nLinear cryptanalysis\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nSide-channel attacks (timing, power)\r\n\r\n4\r\n\r\nModerate resistance (implementation-dependent)\r\n\r\nReplay attack\r\n\r\n5\r\n\r\nStrong resistance (asymmetric model prevents re-encryption; fresh keyA ensures uniqueness)\r\n\r\nPadding oracle attack\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nStructure leakage (message length, alignment)\r\n\r\n5\r\n\r\nStrong resistance (output structure reflects navigation, not plaintext layout)\r\n\r\nCollision attack\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nQuantum resistance\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nLegend:\r\n\r\n5 — Strong resistance: no known structural exposure or attack surface in this category.\r\n\r\n4 — Moderate resistance: some edge-case scenarios might apply; depends on usage.\r\n\r\n3 — Neutral: depends heavily on implementation details or environment.\r\n\r\n2 — Some exposure: partial vulnerability or exploitable in specific scenarios.\r\n\r\n1 — Vulnerable: known attack path likely to succeed.\r\n\r\nDirective: This canvas is now active and will remain unchanged unless explicitly directed.";
var testInput = new string('a', 5);
//var testInput = new string('a', 3);
var test = System.Text.Encoding.UTF8.GetBytes(testInput);

var k2 = RobinsonEncryptionLib.RE.CreateKey();

var mapped = k2.MapData (test, 100);

var unmapped = k2.UnmapData(mapped, 100);

var rok = k2.CreateReadOnlyKey();

var mapped2 = k2.MapData (test, 100);

mapped2.Position = 0;

//var unmapped2 = rok.UnmapData(mapped2, 100);

var rokp = rok.ToBytes();

var rok2 = new REReadOnlyKey(rokp);

mapped.Position = 0;
//var unmapped3 = rok2.UnmapData(mapped, 100);

var sw = System.Diagnostics.Stopwatch.StartNew();
var sw2 = System.Diagnostics.Stopwatch.StartNew();
for (int i = 0; i < 100; i++)
{

    sw.Restart();
    var enc = RE.Encrypt(test, k2 );

    System.Diagnostics.Debug.WriteLine(Convert.ToBase64String(enc), "Encrypted test");

    enc.Position = 0;
    var dec = RE.Decrypt(enc, rok);

    //System.Diagnostics.Debug.WriteLine(System.Text.Encoding.UTF8.GetString(dec), "Decrypted test");
    //dec.Position = 0;
    if (!test.AsSpan().SequenceEqual(dec.AsReadOnlySpan)) System.Diagnostics.Debugger.Break();

    //Console.WriteLine($"Time for iteration #{i}: {sw.ElapsedMilliseconds} ms");
    sw.Restart();
}

sw.Stop();
Console.WriteLine($"Time: {sw2.ElapsedMilliseconds} ms");
return;




public static class XorFoldingCodec
{
    public static List<byte[]> Encode(List<byte[]> blocks)
    {
        var result = new List<byte[]>();
        if (blocks.Count == 0) return result;

        // Store the first block as-is
        result.Add(blocks[0]);

        for (int i = 1; i < blocks.Count; i++)
        {
            var prev = blocks[i - 1];
            var curr = blocks[i];

            // XOR first 3 bytes of curr with last 3 of prev
            byte[] folded = new byte[4];
            folded[0] = (byte)(curr[0] ^ prev[1]);
            folded[1] = (byte)(curr[1] ^ prev[2]);
            folded[2] = (byte)(curr[2] ^ prev[3]);
            folded[3] = curr[3]; // last byte is stored directly

            result.Add(folded);
        }

        return result;
    }

    public static List<byte[]> Decode(List<byte[]> foldedBlocks)
    {
        var result = new List<byte[]>();
        if (foldedBlocks.Count == 0) return result;

        // First block is original
        result.Add(foldedBlocks[0]);

        for (int i = 1; i < foldedBlocks.Count; i++)
        {
            var prev = result[i - 1];        // previous decoded block
            var folded = foldedBlocks[i];

            byte[] current = new byte[4];
            current[0] = (byte)(folded[0] ^ prev[1]);
            current[1] = (byte)(folded[1] ^ prev[2]);
            current[2] = (byte)(folded[2] ^ prev[3]);
            current[3] = folded[3];

            result.Add(current);
        }

        return result;
    }

    // Test helper
    public static void PrintBlocks(string label, List<byte[]> blocks)
    {
        Console.WriteLine(label);
        int i = 0;
        foreach (var block in blocks)
        {
            Console.WriteLine($"Block {i++}: {BitConverter.ToString(block)}");
        }
        Console.WriteLine();
    }
}
