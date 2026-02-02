using RobinsonEncryptionLib;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


var k1 = RobinsonEncryptionLib.RE.CreateKey(2);
var k2 = RobinsonEncryptionLib.RE.CreateKey(2);

var test = System.Text.Encoding.UTF8.GetBytes("llama");

for (int i = 0; i < 100; i++)
{
Console.WriteLine(test.Length);
Console.WriteLine(BitConverter.ToString(test));
var e1 = k1.MapData(test.AsSpan());
Console.WriteLine(e1.skips.Length);
Console.WriteLine(BitConverter.ToString(e1.skips.ToArray()));
var e11 = k1.UnmapData(e1.skips);
Console.WriteLine(BitConverter.ToString(e11));
var e2 = k1.UnmapData(e1.skips, e1.kStar);
Console.WriteLine(BitConverter.ToString(e2));
Console.WriteLine(System.Text.Encoding.UTF8.GetString(e2));
Console.WriteLine(e2.Length);

}



var enc = RE.Encrypt(test, k1, k2);

var dec = RE.Decrypt(enc, k2);

var decStr = System.Text.Encoding.UTF8.GetString(dec);
Console.WriteLine(decStr);

return;