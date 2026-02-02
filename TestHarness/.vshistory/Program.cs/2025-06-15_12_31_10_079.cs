// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


var k1 = RobinsonEncryptionLib.RE.CreateKey();

var test = System.Text.Encoding.UTF8.GetBytes("This is secret stuff!");

var e1 = k1.CreateDataMap(test.AsSpan());
Console.WriteLine(e1.skips.Length);
Console.WriteLine(BitConverter.ToString(e1.skips.ToArray()));
var e2 = k1.UnmapData(e1.skips, e1.kStar);
Console.WriteLine(System.Text.Encoding.UTF8.GetString(e2));
Console.WriteLine(e2.Length);
