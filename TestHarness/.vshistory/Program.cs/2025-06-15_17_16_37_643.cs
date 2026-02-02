using RobinsonEncryptionLib;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");


REKey? k1=null;
var k2 = RobinsonEncryptionLib.RE.CreateKey(2);

var test = System.Text.Encoding.UTF8.GetBytes("stuff this");
    k1 = RobinsonEncryptionLib.RE.CreateKey(2);


var enc = RE.Encrypt(test, k1, k2);

var dec = RE.Decrypt(enc, k2);

var decStr = System.Text.Encoding.UTF8.GetString(dec);
Console.WriteLine(decStr);

return;