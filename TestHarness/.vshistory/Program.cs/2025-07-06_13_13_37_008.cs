using RobinsonEncryptionLib;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


REKey? k1 = null;

var sigK = CodeBasedSignature.CbeSigner.GenerateRandomKey(1);

var msg = System.Text.Encoding.UTF8.GetBytes("hello");

var cbe=new CodeBasedSignature.CbeSigner(sigK, 2);
var sig = cbe.Sign(msg);
var sig2 = cbe.Verify(msg, sig);



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