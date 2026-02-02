using RobinsonEncryptionLib;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


REKey? k1=null;
var k2 = RobinsonEncryptionLib.RE.CreateKey(2);

var testInput = "stuff this";

for (int i = 0; i < 100; i++)
{


var test = System.Text.Encoding.UTF8.GetBytes(testInput);
    k1 = RobinsonEncryptionLib.RE.CreateKey(2);


var enc = RE.Encrypt(test, k1, k2);

Console.WriteLine($"Encrypted Length: {enc.Length}");
Console.WriteLine(Convert.ToBase64String(enc));

var dec = RE.Decrypt(enc, k2);

var decStr = System.Text.Encoding.UTF8.GetString(dec);
Console.WriteLine(decStr);
Console.WriteLine("Decyption Success?: {0}", decStr == testInput);
}
return;