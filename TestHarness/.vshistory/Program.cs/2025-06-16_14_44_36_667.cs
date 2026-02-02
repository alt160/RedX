using RobinsonEncryptionLib;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


REKey? k1=null;
var k2 = RobinsonEncryptionLib.RE.CreateKey(2);


//var testInput = "Chosen-ciphertext attack (IND-CCA2)\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nBrute-force attack\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nFrequency analysis\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nStatistical analysis (e.g., entropy)\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nDifferential cryptanalysis\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nLinear cryptanalysis\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nSide-channel attacks (timing, power)\r\n\r\n4\r\n\r\nModerate resistance (implementation-dependent)\r\n\r\nReplay attack\r\n\r\n5\r\n\r\nStrong resistance (asymmetric model prevents re-encryption; fresh keyA ensures uniqueness)\r\n\r\nPadding oracle attack\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nStructure leakage (message length, alignment)\r\n\r\n5\r\n\r\nStrong resistance (output structure reflects navigation, not plaintext layout)\r\n\r\nCollision attack\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nQuantum resistance\r\n\r\n5\r\n\r\nStrong resistance\r\n\r\nLegend:\r\n\r\n5 — Strong resistance: no known structural exposure or attack surface in this category.\r\n\r\n4 — Moderate resistance: some edge-case scenarios might apply; depends on usage.\r\n\r\n3 — Neutral: depends heavily on implementation details or environment.\r\n\r\n2 — Some exposure: partial vulnerability or exploitable in specific scenarios.\r\n\r\n1 — Vulnerable: known attack path likely to succeed.\r\n\r\nDirective: This canvas is now active and will remain unchanged unless explicitly directed.";
var testInput = new string('a', 100);
var test = System.Text.Encoding.UTF8.GetBytes(testInput);

var mapped = k2.MapData(test);

var unmapped = k2.UnmapData(mapped.skips);
var unmapped2 = k2.UnmapData(mapped.skips, mapped.kStar);


var sw=System.Diagnostics.Stopwatch.StartNew();
for (int i = 0; i < 100000; i++)
{

    sw.Restart();

    k1 = RobinsonEncryptionLib.RE.CreateKey(2 );

var enc = RE.Encrypt(test, k1, k2);

//Console.WriteLine($"Encrypted Length: {enc.Length}");
//Console.WriteLine(Convert.ToBase64String(enc));
//    Console.WriteLine("");

var dec = RE.Decrypt(enc, k2);

//var decStr = System.Text.Encoding.UTF8.GetString(dec);
//Console.WriteLine(decStr);
   // if (decStr != testInput) System.Diagnostics.Debugger.Break();
    //Console.WriteLine("Decyption Success?: {0}", decStr == testInput);
    Console.WriteLine($"Time for iteration #{i}: {sw.ElapsedMilliseconds} ms");
    sw.Restart();
}

sw.Stop();
Console.WriteLine($"Time: {sw.ElapsedMilliseconds} ms");
return;