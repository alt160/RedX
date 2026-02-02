// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


var k1 = RobinsonEncryptionLib.RE.CreateKey();

var test = new byte[] { 1, 2, 3 };

var e1 = k1.DrawPath(test.AsSpan());
Console.WriteLine(e1.skips.ToArray());
var e2 = k1.FollowPath(e1.skips, e1.kStar);
Console.WriteLine(e2);
Console.WriteLine(e2.Length);
