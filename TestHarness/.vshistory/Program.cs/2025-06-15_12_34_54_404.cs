using RobinsonEncryptionLib;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


var k1 = RobinsonEncryptionLib.RE.CreateKey();
var k2 = RobinsonEncryptionLib.RE.CreateKey();

var test = System.Text.Encoding.UTF8.GetBytes("This is secret stuff!");

Console.WriteLine(test.Length);
Console.WriteLine(BitConverter.ToString(test));
var e1 = k1.CreateDataMap(test.AsSpan());
Console.WriteLine(e1.skips.Length);
Console.WriteLine(BitConverter.ToString(e1.skips.ToArray()));
var e2 = k1.UnmapData(e1.skips, e1.kStar);
Console.WriteLine(System.Text.Encoding.UTF8.GetString(e2));
Console.WriteLine(e2.Length);


var enc = RE.Encrypt(test, k1, k2);

var dec = RE.Decrypt(enc, k2);

var decStr = System.Text.Encoding.UTF8.GetString(dec);
Console.WriteLine(decStr);

return;