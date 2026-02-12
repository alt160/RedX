using ZifikaLib;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Diagnostics;
using System.IO;
using System.Text;
using TextCopy;
// use ZifikaLib.Zifika directly

void WriteLineColor(ConsoleColor color, string text)
{
    var old = Console.ForegroundColor;
    Console.ForegroundColor = color;
    Console.WriteLine(text);
    Console.ForegroundColor = old;
}

/// <summary>
/// Write colored inline text without adding a line break.<br/>
/// Restores the prior console color after writing the segment.<br/>
/// </summary>
void WriteColorInline(ConsoleColor color, string text)
{
    var old = Console.ForegroundColor;
    Console.ForegroundColor = color;
    Console.Write(text);
    Console.ForegroundColor = old;
}

/// <summary>
/// Write a line that may contain glossary term markup in the form [[Term]].<br/>
/// Terms are rendered in cyan while the rest of the line is plain text.<br/>
/// The token [[Zifika]] is rendered as plain text without colorization.<br/>
/// </summary>
void WriteInfoLine(string line)
{
    const string TermStart = "[[";
    const string TermEnd = "]]";

    int idx = 0;
    while (true)
    {
        int start = line.IndexOf(TermStart, idx, StringComparison.Ordinal);
        if (start < 0)
        {
            Console.Write(line.Substring(idx));
            break;
        }
        int end = line.IndexOf(TermEnd, start + TermStart.Length, StringComparison.Ordinal);
        if (end < 0)
        {
            Console.Write(line.Substring(idx));
            break;
        }
        Console.Write(line.Substring(idx, start - idx));
        var term = line.Substring(start + TermStart.Length, end - (start + TermStart.Length));
        if (string.Equals(term, "Zifika", StringComparison.OrdinalIgnoreCase))
            Console.Write(term);
        else
            WriteColorInline(ConsoleColor.Cyan, term);
        idx = end + TermEnd.Length;
        if (idx >= line.Length)
            break;
    }
    Console.WriteLine();
}

/// <summary>
/// Strip glossary term markup (e.g., [[Term]]) from a line, preserving other text and indentation.<br/>
/// Returns the plain-text line for export/clipboard use.<br/>
/// </summary>
string StripTermMarkup(string line)
{
    const string TermStart = "[[";
    const string TermEnd = "]]";

    if (string.IsNullOrEmpty(line)) return line;
    var sb = new StringBuilder(line.Length);
    int idx = 0;
    while (true)
    {
        int start = line.IndexOf(TermStart, idx, StringComparison.Ordinal);
        if (start < 0)
        {
            sb.Append(line.Substring(idx));
            break;
        }
        int end = line.IndexOf(TermEnd, start + TermStart.Length, StringComparison.Ordinal);
        if (end < 0)
        {
            sb.Append(line.Substring(idx));
            break;
        }
        sb.Append(line.Substring(idx, start - idx));
        sb.Append(line.Substring(start + TermStart.Length, end - (start + TermStart.Length)));
        idx = end + TermEnd.Length;
        if (idx >= line.Length)
            break;
    }
    return sb.ToString();
}

// recent artifacts for copy/paste convenience
string lastSymKeyHex = null;
string lastSymCipherHex = null;
string lastSymPlainHex = null;
string lastMintHex = null;
string lastVerifierHex = null;
string lastMintCipherHex = null;
string lastMintPlainHex = null;

bool showMintVerifyIntro = true;
bool attackSimulationDetail = false;

const string GlossaryLabel = "Learn more / Glossary of terms";
const string GlossaryContextMain = "main";
const string GlossaryContextSymmetric = "symmetric";
const string GlossaryContextMintVerify = "mint-verify";
const string GlossaryContextSymmetricKey = "symmetric-key";
const string GlossaryContextMintVerifyKey = "mint-verify-key";

const string GlossaryPrimerSource = @"[[Zifika]] Primer

  [[Overview]]
    [[Zifika]] is a symmetric cipher construction based
    on deterministic [[Traversal]] over a two-
    dimensional permutation grid. [[Cipherbytes]]
    are the result of relative traversal distances rather than
    transformed plaintext values.

  [[Core Concepts]]

    [[Plainbytes]]
      [[Plainbytes]] are byte values consumed during
      [[Traversal]]. They include user input bytes
      and injected bytes such as [[PrefixBytes]] and
      [[StartLocation]] encodings. All [[Plainbytes]]
      are processed uniformly.

    [[Cipherbytes]]
      [[Cipherbytes]] are the distance values between
      successive traversal landing positions within
      a single 256-byte key row. They do not represent
      transformed plaintext values.

    [[Traversal]]
      [[Traversal]] is the deterministic process of
      advancing through the [[ZifikaKey]] grid using
      jump values, landing positions, and offset
      emission.

    [[JumpStream]]
      The [[JumpStream]] is a deterministic sequence
      of jump values derived from [[ZifikaKey]] and
      per-execution inputs. Jump values are
      independent of [[Plainbytes]].

    [[LandingSemantics]]
      Each jump produces a landing position within
      the current key row. A [[Cipherbyte]] is emitted
      as the forward wrapped distance to the target
      column selected by the current [[Plainbyte]].

    [[RowAdvancement]]
      After each landing and emission, traversal
      advances to the next key row deterministically,
      modulo the total row count.

  [[Start Location And Prefixes]]

    [[StartLocation]]
      The [[StartLocation]] is a per-execution value
      that establishes the initial traversal origin.
      Its encoded bytes are consumed as [[Plainbytes]]
      across multiple traversal steps.

    [[PrefixBytes]]
      [[PrefixBytes]] are a per-execution sequence of
      injected [[Plainbytes]] consumed before user
      input. They are indistinguishable from user
      input during traversal.

  [[Input And Plainbytes]]

    [[Input]]
      [[Input]] to [[Zifika]] is an ordered sequence of
      bytes. Any byte that participates in traversal
      is a [[Plainbyte]].

    [[PlainbyteSources]]
      [[Plainbytes]] include user input bytes,
      [[PrefixBytes]], [[StartLocation]] bytes, and
      other injected per-execution values. Source
      does not affect traversal behavior.

  [[Integrity]]

    [[IntegritySeal]]
      The [[IntegritySeal]] is an optional per-
      execution mechanism that binds ciphertext
      validity to traversal replay. The seal is
      mapped under the same traversal machinery.

    [[FailClosedBehavior]]
      If [[IntegritySeal]] validation fails during
      decryption, traversal replay halts and no
      plaintext output is produced.

  [[Keys]]

    [[ZifikaKey]]

      [[WhatItIs]]

        [[SerializedForm]]
          A [[ZifikaKey]] is represented as a two-
          dimensional grid of bytes. Each row is
          exactly 256 bytes wide and is a permutation
          of values 0–255.

        [[ExecutionForm]]
          In execution form, a [[ZifikaKey]] exists as
          traversal-defining state. It deterministically
          defines jump generation, landing behavior,
          and offset emission.

      [[WhatItIsNot]]

        [[SerializedForm]]
          A [[ZifikaKey]] is not a number, scalar, or
          algebraic structure. It does not encode
          block structure or plaintext-dependent
          state.

        [[ExecutionForm]]
          A [[ZifikaKey]] is not a reversible transform,
          block cipher state, or stream cipher seed.

    [[MintingKey]]

      [[WhatItIs]]

        [[SerializedForm]]
          A [[MintingKey]] is a composite key artifact
          containing complete [[ZifikaKey]] base data
          and minting authority material.

        [[ExecutionForm]]
          In execution form, a [[MintingKey]] exists
          as traversal-defining state plus attestation-
          generating capability.

      [[WhatItIsNot]]

        [[SerializedForm]]
          A [[MintingKey]] is not a public key,
          [[VerifierKey]], or standalone signing key.

        [[ExecutionForm]]
          A [[MintingKey]] cannot decrypt or verify
          ciphertext and cannot validate ciphertexts
          minted by other keys.

    [[VerifierKey]]

      [[WhatItIs]]

        [[SerializedForm]]
          A [[VerifierKey]] is a composite, secret key
          artifact containing [[ZifikaKey]] base data
          and verification-only authority material.

        [[ExecutionForm]]
          In execution form, a [[VerifierKey]] exists
          as derived traversal state plus attestation-
          verification capability.

      [[WhatItIsNot]]

        [[SerializedForm]]
          A [[VerifierKey]] is not a [[MintingKey]] and
          does not contain minting authority material.

        [[ExecutionForm]]
          A [[VerifierKey]] cannot generate mint-bound
          attestations or mint acceptable ciphertext.

  [[MintVerifyMode]]

    [[Overview]]
      [[MintVerifyMode]] separates the capability to
      mint acceptable ciphertext from the capability
      to decrypt and validate ciphertext.

    [[RelationshipToSymmetricOperation]]
      [[MintVerifyMode]] builds directly on symmetric
      [[Traversal]] without altering cipher semantics
      or integrity behavior.

    [[IntendedProblemSpace]]
      [[MintVerifyMode]] applies where creation
      authority and consumption capability must be
      separated, such as controlled distribution or
      delegated decryption.

    [[WhatItIsNot]]
      [[MintVerifyMode]] does not define a new
      asymmetric primitive and relies on an existing
      asymmetric signing primitive with non-
      reversible verification roles.

  [[ClaimsAndNonClaims]]

    [[Claims]]
      This document defines [[Zifika]] mechanics,
      invariants, and nomenclature. All claims are
      intended to be falsifiable through analysis or
      implementation.

    [[NonClaims]]
      This document does not present a formal security
      proof, claim post-quantum resistance, or claim
      suitability for production deployment.

    [[ImplementationPosture]]
      The provided implementation exists for
      analysis, critique, experimentation, and proof
      work as a reference realization of described
      mechanics.";

GlossaryNode glossaryMenuRoot = null;
GlossaryNode glossaryFileRoot = null;
Dictionary<string, List<GlossaryNode>> glossaryLookup = null;
Dictionary<string, string> glossaryTokenRedirects = new(StringComparer.OrdinalIgnoreCase)
{
    ["PlainByte"] = "Input",
    ["CipherByte"] = "Cipherbytes",
    ["KeyBaseData"] = "ZifikaKey"
};

string[] infoCorePathWalking = new[]
{
    "Zifika uses an internal [[Jump stream]] to drive a walk over a keyed 2D permutation grid.",
    "Each landing emits a [[Key-row offset stream]] value in the same key row.",
    "Ciphertext is the [[Key-row offset stream]], not the [[Jump stream]].",
    "Decryption regenerates the [[Jump stream]] and replays the walk to recover bytes.",
    "This [[path-walking]] design is the root of symmetric and [[Mint/Verify mode]] behavior."
};

string[] infoPrimerIntro = new[]
{
    "Zifika is an experimental [[path-walking]] cipher intended for analysis and review only.",
    "It uses an internal [[Jump stream]] and outputs a [[Key-row offset stream]] as ciphertext.",
    "It is not production-ready and must not be used in security-critical systems.",
    "Ciphertext is the output of a keyed traversal across a 2D permutation grid; decryption replays that walk to recover plaintext.",
    "This primer focuses on usage and capability boundaries; construction details are in the source."
};

string[] infoMintVerifyIntro = new[]
{
    "[[Mint/Verify mode]] in Zifika refers to separated capabilities: minting vs verifying.",
    "The roles are intentionally inverted: the verifier key can decrypt and verify that the ciphertext was minted by its paired minting key.",
    "If verification fails, no output is produced.",
    "Verification uses a standard asymmetric signature primitive, applied to the traversal transcript in a Zifika-specific way.",
    "The minting key creates ciphertexts and emits a signed traversal transcript (a record of work performed, not plaintext or ciphertext).",
    "This is a capability policy enforced by the [[path-walking]] construction and encoded traversal metadata.",
    "Mint/Verify behavior is not a cryptographic bar on encrypting what you can decrypt; it is a capability lock that prevents ciphertext minted without the paired minting key from validating.",
    "Authority here is embedded in the minting/verifier keypair, not an external authority."
};

string[] infoJumpStream = new[]
{
    "[[Jump stream]] is the internal sequence of row/col jumps produced by a pseudorandom generator.",
    "It is derived from the key and the [[Interference catalyst]] for each execution.",
    "It is not stored in ciphertext and cannot be recovered from ciphertext alone.",
    "It exists only during execution to drive landing positions with a [[Random Start Location]]."
};

string[] infoKeyRowOffsetStream = new[]
{
    "[[Key-row offset stream]] is the wrapped distance from each landing byte to the byte matching the next plaintext byte in the same key row.",
    "It is the ciphertext payload written to the wire.",
    "It varies per execution because [[Random Start Location]] and [[Interference catalyst]] change.",
    "Decryption regenerates the [[Jump stream]] and applies these offsets to recover plaintext.",
    "It records traversal offsets, not plaintext bytes."
};

string[] infoInterferenceCatalyst = new[]
{
    "[[Interference catalyst]] is a per-execution random header value.",
    "It is encrypted in the header and mixed into the walk.",
    "It seeds the pseudorandom jump generator and binds the integrity seal.",
    "It is unique per execution, even for the same key and same plaintext.",
    "It forces divergent traversals across repeated inputs."
};

string[] infoRandomStartLocation = new[]
{
    "[[Random Start Location]] is the per-execution origin of the walk.",
    "It is encrypted in the header and selects the payload path.",
    "It is unique per execution, even for the same key and same plaintext.",
    "It prevents fixed-position leakage and keeps output non-repeatable.",
    "It separates header mapping from payload mapping."
};

string[] infoCiphertextProductionOverview = new[]
{
    "Ciphertext is produced by a traversal; the payload is a [[Key-row offset stream]].",
    "Header fields are mapped at fixed positions (pos-0 or [[Interference catalyst]] length).",
    "Payload is mapped from a [[Random Start Location]].",
    "The [[Jump stream]] is internal and not written to ciphertext.",
    "No plaintext bytes are stored or signed directly.",
    "[[Mint/Verify mode]] signs the traversal transcript, not plaintext."
};

string[] infoCiphertextUniqueness = new[]
{
    "Ciphertext is the encoded movement across a permutation, not substituted bytes.",
    "[[Random Start Location]] and [[Interference catalyst]] change per execution, even for the same key and same plaintext.",
    "The [[Key-row offset stream]] depends on the internal [[Jump stream]] and header inputs.",
    "Traversal and mapping are coupled; there is no static block transform.",
    "This yields a non-linear relation between input, key, and output."
};

string[] infoPlaintextSizePerf = new[]
{
    "Per-byte cost is constant; total cost scales linearly with size.",
    "Overhead is fixed per message, not per byte.",
    "The security profile is size-agnostic within the design.",
    "No additional guarantees are claimed for larger inputs."
};

string[] infoKeySizingMinDefault = new[]
{
    "Key size equals the number of 256-byte rows in the permutation grid.",
    "Minimum safe size: 2 blocks (512 bytes).",
    "Default in the demo: 8 blocks (2048 bytes).",
    "Recompiling is not required to change key size."
};

string[] infoKeySizingLarge = new[]
{
    "Per-byte cost is constant across key sizes.",
    "A 1MB key performs similarly to a 512-byte key.",
    "Large keys increase state, not per-byte work.",
    "Use larger keys when storage and transport allow."
};

string[] infoIntegrityModeWhat = new[]
{
    "[[Integrity mode]] adds an integrity seal over [[Key-row offset stream]] + [[Interference catalyst]].",
    "The seal is unique per execution, even for the same key and same plaintext.",
    "When enabled, decrypt requires a valid seal.",
    "Missing or invalid seals return null.",
    "This provides tamper/corruption detection without releasing plaintext.",
    "This is distinct from authority checkpoints."
};

string[] infoIntegrityModeWhy = new[]
{
    "Any change to [[Key-row offset stream]] or [[Interference catalyst]] changes the seal.",
    "The seal is mapped under the same keying as the payload.",
    "This binds integrity to the walk, not to plaintext bytes."
};

string[] infoIntegrityModeIndCca = new[]
{
    "Strict reject-on-failure aligns with IND-CCA expectations.",
    "Returning null is deliberate: no plaintext is emitted without a valid integrity seal.",
    "This is analogous to AEAD, but with Zifika mapping semantics."
};

string[] infoIntegrityModeVsMintVerify = new[]
{
    "[[Integrity mode]] is symmetric integrity only (tamper/corruption detection).",
    "[[Mint/Verify mode]] is a capability model (mint vs verify).",
    "They can be used together: [[Mint/Verify mode]] + integrity seal."
};

string[] infoKeysContain = new[]
{
    "Full key: permutation grid + hash + derivation material.",
    "verifier (VerifierKey) : key hash + per-position nonces + lookup map.",
    "Minting key: full key + authority signing keypair.",
    "Verifier key: VerifierKey + authority public key only."
};

string[] infoKeysLifecycle = new[]
{
    "Keys can be serialized to blobs and rehydrated.",
    "Minting/verifier blobs include authority key material.",
    "Treat key blobs as secrets; protect at rest and in transit.",
    "Verifier keys can be shared without minting material."
};

string[] infoCiphertextContains = new[]
{
    "Contains: encrypted header, [[Key-row offset stream]], optional integrity seal.",
    "[[Mint/Verify mode]] includes signed traversal transcript (checkpoints).",
    "The [[Jump stream]] is internal and not stored.",
    "Does not contain plaintext or direct plaintext transforms.",
    "Does not contain the key or permutation."
};

string[] infoMintVerifyName = new[]
{
    "[[Mint/Verify mode]] refers to inverted capabilities, not asymmetric encryption.",
    "Verifier decrypts and verifies; minter encrypts and mints.",
    "Verifier cannot mint valid ciphertexts."
};

string[] infoMintVerifyUseCases = new[]
{
    "Software licensing and delegated read access.",
    "Escrowed decryption with provenance.",
    "Controlled distribution where minting is centralized."
};

string[] infoMintVerifyLimits = new[]
{
    "Verifier cannot mint new valid ciphertexts.",
    "Not a signature scheme or general-purpose PKI.",
    "Requires authority key for provenance validation."
};

string[] infoAuthorityTerminology = new[]
{
    "Authority is embedded in the minting/verifier keypair.",
    "It is not an external service or trusted third party.",
    "Checkpoints sign traversal state, not plaintext."
};

string[] infoClaimsNonClaims = new[]
{
    "Security strength not yet determined; no formal proof or independent audit.",
    "This release is intended to begin formal analysis and proof work.",
    "PAI here means post-AI cryptanalysis (AI/ML-aided cryptanalysis).",
    "Not claiming post-quantum or post-AI (PAI) resistance.",
    "Not yet analyzed against standard cryptanalysis families; public analysis invited."
};

string[] infoFailureSemantics = new[]
{
    "Integrity check failure returns null.",
    "Authority verification failure returns null.",
    "No plaintext is emitted on failure."
};

string[] infoWirePhysicalLogical = new[]
{
    "Physical layout is a byte stream with minimal framing.",
    "Only [[Interference catalyst]] length (and vKeyLock in [[Mint/Verify mode]]) are plaintext; other fields are mapped.",
    "Logical structure appears in two phases:",
    "1) decode control fields at fixed positions,",
    "2) decode payload from a [[Random Start Location]] into a [[Key-row offset stream]].",
    "Intuition: fixed + random mapping creates an interference pattern across the walk."
};

string[] infoWireSymmetric = new[]
{
    "Symmetric (integrity off): enc(startLoc) | intCatLen | enc(intCat) | [[Key-row offset stream]]",
    "Symmetric (integrity on):  enc(startLoc) | intCatLen | enc(intCat) | [[Key-row offset stream]] | enc(seal)",
    "[[Random Start Location]] is mapped at pos-0; [[Interference catalyst]] is mapped at pos-intCatLen.",
    "Payload [[Key-row offset stream]] is mapped from the [[Random Start Location]]."
};

string[] infoWireMintVerify = new[]
{
    "[[Mint/Verify mode]] (integrity off): vKeyLock | enc(startLoc) | enc(ckCount) | enc(sigs) | intCatLen | enc(intCat) | [[Key-row offset stream]]",
    "[[Mint/Verify mode]] (integrity on):  vKeyLock | enc(startLoc) | enc(ckCount) | enc(sigs) | intCatLen | enc(intCat) | [[Key-row offset stream]] | enc(seal)",
    "Control stream is verifier-mapped using vKeyLock at pos-0.",
    "Payload [[Key-row offset stream]] is mapped from the [[Random Start Location]]."
};

string[] infoWireHeaderFields = new[]
{
    "vKeyLock: per-message binder for control stream mapping.",
    "[[Random Start Location]]: encrypted at pos-0; selects payload walk origin.",
    "[[Interference catalyst]]: encrypted at pos-intCatLen; mixes into mapping for replay resistance.",
    "In [[Mint/Verify mode]], [[Random Start Location]] is mapped under vKeyLock for verifier recovery.",
    "vKeyLock remains plaintext to bootstrap header decode."
};

var breadcrumb = new List<string> { "Main" };
/// <summary>
/// Print the current breadcrumb path using a single line label.<br/>
/// Uses the provided path when supplied; otherwise uses the global breadcrumb list.<br/>
/// Token markup is stripped for readability and a root is enforced when empty.<br/>
/// </summary>
void PrintBreadcrumb(IEnumerable<string> path = null)
{
    var items = new List<string>();
    if (path != null)
    {
        foreach (var entry in path)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            items.Add(StripTermMarkup(entry).Trim());
        }
    }
    else if (breadcrumb != null)
    {
        foreach (var entry in breadcrumb)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            items.Add(StripTermMarkup(entry).Trim());
        }
    }

    if (items.Count == 0)
        items.Add("Main");

    WriteLineColor(ConsoleColor.Yellow, $"Path: {string.Join(" > ", items)}");
}

/// <summary>
/// Build a breadcrumb list by appending tail segments to the global base path.<br/>
/// Ensures a root entry exists even if the base path is empty or null.<br/>
/// </summary>
List<string> BuildBreadcrumbPath(params string[] tail)
{
    var path = new List<string>();
    if (breadcrumb != null && breadcrumb.Count > 0)
        path.AddRange(breadcrumb);
    else
        path.Add("Main");

    if (tail != null)
    {
        foreach (var item in tail)
        {
            if (string.IsNullOrWhiteSpace(item)) continue;
            path.Add(item);
        }
    }
    return path;
}

/// <summary>
/// Build a breadcrumb path for the glossary menu rooted at the glossary label.<br/>
/// Includes the active glossary node path from root to the current node.<br/>
/// </summary>
List<string> BuildGlossaryBreadcrumb(GlossaryNode node)
{
    var path = BuildBreadcrumbPath(GlossaryLabel);
    if (node == null || ReferenceEquals(node, glossaryMenuRoot)) return path;

    var stack = new Stack<GlossaryNode>();
    var cursor = node;
    while (cursor != null && !ReferenceEquals(cursor, glossaryMenuRoot))
    {
        stack.Push(cursor);
        cursor = cursor.Parent;
    }
    while (stack.Count > 0)
        path.Add(stack.Pop().TitleRaw);

    return path;
}

/// <summary>
/// Temporarily append a breadcrumb segment for the duration of an action.<br/>
/// Always restores the prior breadcrumb list even if the action throws.<br/>
/// </summary>
void WithBreadcrumb(string crumb, Action action)
{
    bool added = false;
    if (!string.IsNullOrWhiteSpace(crumb))
    {
        breadcrumb.Add(crumb);
        added = true;
    }
    try
    {
        action();
    }
    finally
    {
        if (added && breadcrumb.Count > 0)
            breadcrumb.RemoveAt(breadcrumb.Count - 1);
    }
}

bool TrySetClipboard(string label, string text)
{
    try
    {
        ClipboardService.SetText(text);
        Console.WriteLine($" {label} copied to clipboard.");
        return true;
    }
    catch (Exception ex)
    {
        Console.WriteLine($" Clipboard copy failed: {ex.Message}");
        return false;
    }
}

bool TryGetClipboardHex(out byte[] bytes, out string hex)
{
    bytes = null;
    hex = null;
    try
    {
        var txt = ClipboardService.GetText();
        if (string.IsNullOrWhiteSpace(txt)) return false;
        var normalized = NormalizeHex(txt);
        if (normalized == null) return false;
        bytes = normalized;
        hex = Convert.ToHexString(bytes);
        return true;
    }
    catch
    {
        return false;
    }
}

/// <summary>
/// Normalize a hex string: strip 0x prefix, remove spaces/dashes/colons, require even length; returns null on failure.<br/>
/// </summary>
byte[] NormalizeHex(string input)
{
    if (string.IsNullOrWhiteSpace(input)) return null;
    var sb = new StringBuilder(input.Length);
    var s = input.Trim();
    if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        s = s.Substring(2);
    foreach (var ch in s)
    {
        if (ch == ' ' || ch == '-' || ch == ':' || ch == '\t' || ch == '\r' || ch == '\n')
            continue;
        sb.Append(ch);
    }
    if ((sb.Length & 1) != 0) return null;
    try
    {
        return Convert.FromHexString(sb.ToString());
    }
    catch
    {
        return null;
    }
}

void CopyNow(string label, string hex)
{
    if (hex == null)
    {
        Console.WriteLine($" No {label} available to copy.");
        return;
    }
    TrySetClipboard(label, hex);
}

/// <summary>
/// Print a short clinical primer intro and safety notice before the main menu.<br/>
/// </summary>
void PrintPrimerIntro()
{
    WriteLineColor(ConsoleColor.Cyan, "Zifika primer");
    foreach (var line in infoPrimerIntro)
        WriteInfoLine(line);
}

/// <summary>
/// Print the anti-symmetric intro and optionally disable future prompts for this session.<br/>
/// </summary>
void ShowMintVerifyIntro(ref bool showAgain)
{
    Console.WriteLine();
    PrintBreadcrumb(BuildBreadcrumbPath("Mint/Verify intro"));
    WriteLineColor(ConsoleColor.Cyan, "Mint/Verify mode overview");
    foreach (var line in infoMintVerifyIntro)
        WriteInfoLine(line);
    var choice = ReadChoiceKey("Show this intro next time? (Y/N): ", "Y", "N");
    if (string.Equals(choice, "N", StringComparison.OrdinalIgnoreCase))
        showAgain = false;
}

/// <summary>
/// Pause so the user can read a short info block before returning to the prior menu.<br/>
/// </summary>
void PauseForReturn()
{
    Console.WriteLine();
    Console.Write("Press any key to return...");
    Console.ReadKey(intercept: true);
    Console.WriteLine();
}

/// <summary>
/// Display a titled info block with short lines and return on keypress.<br/>
/// </summary>
void ShowInfo(string title, string[] lines)
{
    Console.WriteLine();
    WriteLineColor(ConsoleColor.Cyan, title);
    foreach (var line in lines)
        WriteInfoLine(line);
    PauseForReturn();
}

/// <summary>
/// Build a hierarchy-indented glossary tree with glossary term markup preserved.<br/>
/// Uses tabs for indentation and deduplicates text across sections.<br/>
/// </summary>
List<string> BuildFullGlossaryTreeLines()
{
    EnsureGlossaryLoaded();
    var lines = new List<string>();
    var seen = new HashSet<string>(StringComparer.Ordinal);

    void AddLine(int indent, string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        var line = new string('\t', indent) + text;
        var key = StripTermMarkup(line).Trim();
        if (key.Length == 0) return;
        if (seen.Add(key))
            lines.Add(line);
    }

    void Walk(GlossaryNode node, int indent)
    {
        AddLine(indent, node.TitleRaw);
        foreach (var text in node.TextLines)
            AddLine(indent + 1, text);
        foreach (var child in node.Children)
            Walk(child, indent + 1);
    }

    AddLine(0, GlossaryLabel);
    foreach (var child in glossaryMenuRoot.Children)
        Walk(child, 1);

    return lines;
}

/// <summary>
/// Render the full glossary tree to the console with term highlighting.<br/>
/// Uses tab indentation to reflect hierarchy and pauses for return.<br/>
/// </summary>
void ShowFullGlossaryTree()
{
    Console.WriteLine();
    WriteLineColor(ConsoleColor.Cyan, "Full glossary tree");
    foreach (var line in BuildFullGlossaryTreeLines())
        WriteInfoLine(line);
    PauseForReturn();
}

/// <summary>
/// Copy the full glossary tree to the clipboard as plain text with tab indentation.<br/>
/// Glossary term markup (e.g., [[Term]]) is preserved in the export.<br/>
/// </summary>
void CopyFullGlossaryTreeToClipboard()
{
    var sb = new StringBuilder();
    foreach (var line in BuildFullGlossaryTreeLines())
        sb.AppendLine(line);
    var text = sb.ToString().TrimEnd();
    TrySetClipboard("Full glossary tree", text);
}

/// <summary>
/// Show a context-aware glossary menu and allow quick access to common topics.<br/>
/// </summary>
void RunGlossaryMenu(string context)
{
    EnsureGlossaryLoaded();
    RunGlossaryMenuInternal(glossaryMenuRoot);
}

/// <summary>
/// Show the full glossary index and route into specific submenus or topics.<br/>
/// </summary>
void RunGlossaryIndex()
{
    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, GlossaryLabel);
        Console.WriteLine("  A) Core design: path-walking");
        Console.WriteLine("  B) Jump stream");
        Console.WriteLine("  C) Key-row offset stream");
        Console.WriteLine("  D) Interference catalyst");
        Console.WriteLine("  E) Random Start Location");
        Console.WriteLine("  F) Ciphertext production");
        Console.WriteLine("  G) Plaintext size & performance");
        Console.WriteLine("  H) Key sizing & variability");
        Console.WriteLine("  I) Integrity mode");
        Console.WriteLine("  J) Keys: what they contain");
        Console.WriteLine("  K) Ciphertext: contains / does not contain");
        Console.WriteLine("  L) Mint/Verify mode");
        Console.WriteLine("  M) Claims & non-claims");
        Console.WriteLine("  N) Failure semantics");
        Console.WriteLine("  O) Wire format");
        Console.WriteLine("  T) View full glossary tree");
        Console.WriteLine("  Y) Copy full glossary tree");
        Console.WriteLine("  X) Back");
        var choice = ReadChoiceKey("Select (A-O/T/Y/X or ESC): ", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "T", "Y", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) ShowInfo("Core: path-walking", infoCorePathWalking);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) ShowInfo("Jump stream", infoJumpStream);
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase)) ShowInfo("Key-row offset stream", infoKeyRowOffsetStream);
        else if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase)) ShowInfo("Interference catalyst", infoInterferenceCatalyst);
        else if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase)) ShowInfo("Random Start Location", infoRandomStartLocation);
        else if (string.Equals(choice, "F", StringComparison.OrdinalIgnoreCase)) RunGlossaryCiphertextMenu();
        else if (string.Equals(choice, "G", StringComparison.OrdinalIgnoreCase)) ShowInfo("Plaintext size & performance", infoPlaintextSizePerf);
        else if (string.Equals(choice, "H", StringComparison.OrdinalIgnoreCase)) RunGlossaryKeySizingMenu();
        else if (string.Equals(choice, "I", StringComparison.OrdinalIgnoreCase)) RunGlossaryIntegrityMenu();
        else if (string.Equals(choice, "J", StringComparison.OrdinalIgnoreCase)) RunGlossaryKeysMenu();
        else if (string.Equals(choice, "K", StringComparison.OrdinalIgnoreCase)) ShowInfo("Ciphertext contents", infoCiphertextContains);
        else if (string.Equals(choice, "L", StringComparison.OrdinalIgnoreCase)) RunGlossaryMintVerifyMenu();
        else if (string.Equals(choice, "M", StringComparison.OrdinalIgnoreCase)) ShowInfo("Claims & non-claims", infoClaimsNonClaims);
        else if (string.Equals(choice, "N", StringComparison.OrdinalIgnoreCase)) ShowInfo("Failure semantics", infoFailureSemantics);
        else if (string.Equals(choice, "O", StringComparison.OrdinalIgnoreCase)) RunGlossaryWireMenu();
        else if (string.Equals(choice, "T", StringComparison.OrdinalIgnoreCase)) ShowFullGlossaryTree();
        else if (string.Equals(choice, "Y", StringComparison.OrdinalIgnoreCase)) CopyFullGlossaryTreeToClipboard();
    }
}

/// <summary>
/// Show short entries about how ciphertext is produced and why it is unique.<br/>
/// </summary>
void RunGlossaryCiphertextMenu()
{
    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Ciphertext production");
        Console.WriteLine("  A) How ciphertext is produced");
        Console.WriteLine("  B) Why the result is unique");
        Console.WriteLine("  C) Jump stream");
        Console.WriteLine("  D) Key-row offset stream");
        Console.WriteLine("  E) Interference catalyst");
        Console.WriteLine("  F) Random Start Location");
        Console.WriteLine("  G) Mint/Verify mode");
        Console.WriteLine("  X) Back");
        var choice = ReadChoiceKey("Select (A-G/X or ESC): ", "A", "B", "C", "D", "E", "F", "G", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) ShowInfo("Ciphertext production", infoCiphertextProductionOverview);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) ShowInfo("Why this is unique", infoCiphertextUniqueness);
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase)) ShowInfo("Jump stream", infoJumpStream);
        else if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase)) ShowInfo("Key-row offset stream", infoKeyRowOffsetStream);
        else if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase)) ShowInfo("Interference catalyst", infoInterferenceCatalyst);
        else if (string.Equals(choice, "F", StringComparison.OrdinalIgnoreCase)) ShowInfo("Random Start Location", infoRandomStartLocation);
        else if (string.Equals(choice, "G", StringComparison.OrdinalIgnoreCase)) RunGlossaryMintVerifyMenu();
    }
}

/// <summary>
/// Show short entries about key sizing and variability.<br/>
/// </summary>
void RunGlossaryKeySizingMenu()
{
    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Key sizing & variability");
        Console.WriteLine("  A) Minimum and default sizes");
        Console.WriteLine("  B) Large keys and performance");
        Console.WriteLine("  X) Back");
        var choice = ReadChoiceKey("Select (A/B/X or ESC): ", "A", "B", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) ShowInfo("Key sizing: minimum and default", infoKeySizingMinDefault);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) ShowInfo("Key sizing: large keys", infoKeySizingLarge);
    }
}

/// <summary>
/// Show short entries about integrity mode and its guarantees.<br/>
/// </summary>
void RunGlossaryIntegrityMenu()
{
    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Integrity mode");
        Console.WriteLine("  A) What it is");
        Console.WriteLine("  B) Why it works");
        Console.WriteLine("  C) IND-CCA / IND-CCA2 alignment");
        Console.WriteLine("  D) Relation to Mint/Verify mode");
        Console.WriteLine("  E) Jump stream");
        Console.WriteLine("  F) Key-row offset stream");
        Console.WriteLine("  G) Interference catalyst");
        Console.WriteLine("  H) Mint/Verify mode");
        Console.WriteLine("  X) Back");
        var choice = ReadChoiceKey("Select (A-H/X or ESC): ", "A", "B", "C", "D", "E", "F", "G", "H", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) ShowInfo("Integrity mode: what it is", infoIntegrityModeWhat);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) ShowInfo("Integrity mode: why it works", infoIntegrityModeWhy);
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase)) ShowInfo("Integrity mode: IND-CCA alignment", infoIntegrityModeIndCca);
        else if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase)) ShowInfo("Integrity vs Mint/Verify", infoIntegrityModeVsMintVerify);
        else if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase)) ShowInfo("Jump stream", infoJumpStream);
        else if (string.Equals(choice, "F", StringComparison.OrdinalIgnoreCase)) ShowInfo("Key-row offset stream", infoKeyRowOffsetStream);
        else if (string.Equals(choice, "G", StringComparison.OrdinalIgnoreCase)) ShowInfo("Interference catalyst", infoInterferenceCatalyst);
        else if (string.Equals(choice, "H", StringComparison.OrdinalIgnoreCase)) RunGlossaryMintVerifyMenu();
    }
}

/// <summary>
/// Show short entries about key contents and lifecycle handling.<br/>
/// </summary>
void RunGlossaryKeysMenu()
{
    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Keys");
        Console.WriteLine("  A) What keys contain");
        Console.WriteLine("  B) Serialization and lifecycle");
        Console.WriteLine("  X) Back");
        var choice = ReadChoiceKey("Select (A/B/X or ESC): ", "A", "B", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) ShowInfo("Keys: contents", infoKeysContain);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) ShowInfo("Keys: lifecycle", infoKeysLifecycle);
    }
}

/// <summary>
/// Show short entries about Mint/Verify mode and its constraints.<br/>
/// </summary>
void RunGlossaryMintVerifyMenu()
{
    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Mint/Verify mode");
        Console.WriteLine("  A) Why the name");
        Console.WriteLine("  B) Use cases");
        Console.WriteLine("  C) What it cannot do");
        Console.WriteLine("  D) Authority terminology");
        Console.WriteLine("  X) Back");
        var choice = ReadChoiceKey("Select (A-D/X or ESC): ", "A", "B", "C", "D", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) ShowInfo("Mint/Verify: name and meaning", infoMintVerifyName);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) ShowInfo("Mint/Verify use cases", infoMintVerifyUseCases);
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase)) ShowInfo("Mint/Verify limits", infoMintVerifyLimits);
        else if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase)) ShowInfo("Authority terminology", infoAuthorityTerminology);
    }
}

/// <summary>
/// Show short entries describing the wire format and its structure.<br/>
/// </summary>
void RunGlossaryWireMenu()
{
    while (true)
    {
        Console.WriteLine();
        WriteLineColor(ConsoleColor.Cyan, "Wire format");
        Console.WriteLine("  A) Physical vs logical structure");
        Console.WriteLine("  B) Symmetric layout");
        Console.WriteLine("  C) Mint/Verify layout");
        Console.WriteLine("  D) Header fields and roles");
        Console.WriteLine("  E) Jump stream");
        Console.WriteLine("  F) Key-row offset stream");
        Console.WriteLine("  G) Interference catalyst");
        Console.WriteLine("  H) Random Start Location");
        Console.WriteLine("  I) Mint/Verify mode");
        Console.WriteLine("  X) Back");
        var choice = ReadChoiceKey("Select (A-I/X or ESC): ", "A", "B", "C", "D", "E", "F", "G", "H", "I", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) ShowInfo("Wire format: physical vs logical", infoWirePhysicalLogical);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) ShowInfo("Wire format: symmetric", infoWireSymmetric);
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase)) ShowInfo("Wire format: mint/verify", infoWireMintVerify);
        else if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase)) ShowInfo("Header fields", infoWireHeaderFields);
        else if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase)) ShowInfo("Jump stream", infoJumpStream);
        else if (string.Equals(choice, "F", StringComparison.OrdinalIgnoreCase)) ShowInfo("Key-row offset stream", infoKeyRowOffsetStream);
        else if (string.Equals(choice, "G", StringComparison.OrdinalIgnoreCase)) ShowInfo("Interference catalyst", infoInterferenceCatalyst);
        else if (string.Equals(choice, "H", StringComparison.OrdinalIgnoreCase)) ShowInfo("Random Start Location", infoRandomStartLocation);
        else if (string.Equals(choice, "I", StringComparison.OrdinalIgnoreCase)) RunGlossaryMintVerifyMenu();
    }
}

/// <summary>
/// Ensure the glossary tree is parsed, indexed, and validated exactly once.<br/>
/// Builds a synthetic menu root that preserves the current glossary title.<br/>
/// </summary>
void EnsureGlossaryLoaded()
{
    if (glossaryMenuRoot != null) return;

    glossaryFileRoot = ParseGlossaryTree(GlossaryPrimerSource);
    glossaryLookup = BuildGlossaryLookup(glossaryFileRoot);

    var topNodes = glossaryFileRoot.Children;
    if (topNodes.Count == 1 && string.Equals(topNodes[0].TitleKey, "Zifika Primer", StringComparison.OrdinalIgnoreCase))
        topNodes = topNodes[0].Children;

    glossaryMenuRoot = new GlossaryNode
    {
        TitleRaw = GlossaryLabel,
        TitleKey = GlossaryLabel,
        Level = -1,
        Parent = null
    };
    glossaryMenuRoot.Children.AddRange(topNodes);
    foreach (var child in topNodes)
        child.Parent = glossaryMenuRoot;

    ValidateGlossaryTokens();
}

/// <summary>
/// Open the glossary menu directly at a specific node key.<br/>
/// The key may include or omit term markup (e.g., [[Token]]).<br/>
/// </summary>
void RunGlossaryMenuAtKey(string key)
{
    EnsureGlossaryLoaded();
    if (string.IsNullOrWhiteSpace(key))
    {
        RunGlossaryMenuInternal(glossaryMenuRoot);
        return;
    }

    var target = ResolveGlossaryNodeKey(key);
    if (target == null)
        throw new InvalidOperationException($"Glossary entry not found for key: {key}");
    RunGlossaryMenuInternal(target);
}

/// <summary>
/// Drive the glossary menu loop from a given starting node.<br/>
/// Shows the node text, then submenu items, then token jump items.<br/>
/// </summary>
void RunGlossaryMenuInternal(GlossaryNode startNode)
{
    EnsureGlossaryLoaded();
    var origin = startNode ?? glossaryMenuRoot;

    var path = new List<GlossaryNode>();
    var cursor = origin;
    while (cursor != null)
    {
        path.Add(cursor);
        cursor = cursor.Parent;
    }
    path.Reverse();
    var stack = new Stack<GlossaryNode>(path);

    while (stack.Count > 0)
    {
        var node = stack.Peek();
        Console.WriteLine();
        PrintBreadcrumb(BuildGlossaryBreadcrumb(node));
        WriteLineColor(ConsoleColor.Cyan, GlossaryLabel);
        if (!ReferenceEquals(node, glossaryMenuRoot))
            WriteInfoLine(node.TitleRaw);
        foreach (var line in node.TextLines)
            WriteInfoLine(line);

        var menuItems = new List<(string Label, GlossaryNode Target)>();
        foreach (var child in node.Children)
            menuItems.Add((child.TitleRaw, child));
        foreach (var tokenLink in BuildTokenLinks(node))
            menuItems.Add(tokenLink);

        var letters = BuildGlossaryMenuLetters(menuItems.Count, node.TitleKey);
        var choiceMap = new Dictionary<string, GlossaryNode>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < menuItems.Count; i++)
        {
            var letter = letters[i].ToString();
            choiceMap[letter] = menuItems[i].Target;
            WriteInfoLine($"  {letter}) {menuItems[i].Label}");
        }

        Console.WriteLine("  T) View full glossary tree");
        Console.WriteLine("  Y) Copy full glossary tree");
        Console.WriteLine("  X) Back");

        var allowed = new List<string>(choiceMap.Keys) { "T", "Y", "X" };
        var choice = ReadChoiceKey("Select option (or ESC): ", allowed.ToArray());
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase))
        {
            stack.Pop();
            if (stack.Count == 0) return;
            continue;
        }
        if (string.Equals(choice, "T", StringComparison.OrdinalIgnoreCase))
        {
            ShowFullGlossaryTree();
            continue;
        }
        if (string.Equals(choice, "Y", StringComparison.OrdinalIgnoreCase))
        {
            CopyFullGlossaryTreeToClipboard();
            continue;
        }

        if (choiceMap.TryGetValue(choice, out var target))
            stack.Push(target);
    }
}

/// <summary>
/// Parse an indented glossary text block into a node tree.<br/>
/// Lines with deeper indentation become submenu nodes; leaf lines become text blocks.<br/>
/// </summary>
GlossaryNode ParseGlossaryTree(string source)
{
    var root = new GlossaryNode { TitleRaw = "__ROOT__", TitleKey = string.Empty, Level = -1 };
    var lines = new List<(string Text, int Indent)>();

    foreach (var raw in source.Split('\n'))
    {
        var line = raw.TrimEnd('\r');
        if (string.IsNullOrWhiteSpace(line)) continue;
        int indent = 0;
        while (indent < line.Length && line[indent] == ' ')
            indent++;
        var text = line.Substring(indent);
        lines.Add((text, indent));
    }

    var stack = new Stack<GlossaryNode>();
    stack.Push(root);

    for (int i = 0; i < lines.Count; i++)
    {
        var (text, indent) = lines[i];
        int level = indent / 2;
        int nextIndent = i + 1 < lines.Count ? lines[i + 1].Indent : -1;
        bool isHeading = nextIndent > indent;

        if (isHeading)
        {
            while (stack.Peek().Level >= level)
                stack.Pop();
            var node = new GlossaryNode
            {
                TitleRaw = text,
                TitleKey = StripTermMarkup(text).Trim(),
                Level = level,
                Parent = stack.Peek()
            };
            stack.Peek().Children.Add(node);
            stack.Push(node);
        }
        else
        {
            while (stack.Peek().Level >= level)
                stack.Pop();
            stack.Peek().TextLines.Add(text);
        }
    }

    return root;
}

/// <summary>
/// Build a case-insensitive lookup of glossary nodes by stripped title key.<br/>
/// Multiple entries per key are retained for ambiguity detection.<br/>
/// </summary>
Dictionary<string, List<GlossaryNode>> BuildGlossaryLookup(GlossaryNode root)
{
    var lookup = new Dictionary<string, List<GlossaryNode>>(StringComparer.OrdinalIgnoreCase);
    foreach (var node in EnumerateGlossaryNodes(root))
    {
        if (string.IsNullOrWhiteSpace(node.TitleKey)) continue;
        if (!lookup.TryGetValue(node.TitleKey, out var list))
        {
            list = new List<GlossaryNode>();
            lookup[node.TitleKey] = list;
        }
        list.Add(node);
    }
    return lookup;
}

/// <summary>
/// Enumerate all glossary nodes in depth-first order, including the root container.<br/>
/// </summary>
IEnumerable<GlossaryNode> EnumerateGlossaryNodes(GlossaryNode root)
{
    if (root == null) yield break;
    var stack = new Stack<GlossaryNode>();
    stack.Push(root);
    while (stack.Count > 0)
    {
        var node = stack.Pop();
        yield return node;
        for (int i = node.Children.Count - 1; i >= 0; i--)
            stack.Push(node.Children[i]);
    }
}

/// <summary>
/// Validate that all glossary tokens resolve to a unique node after redirects.<br/>
/// Throws if missing or ambiguous targets are discovered.<br/>
/// </summary>
void ValidateGlossaryTokens()
{
    var missing = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
    var ambiguous = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

    foreach (var node in EnumerateGlossaryNodes(glossaryFileRoot))
    {
        foreach (var line in node.TextLines)
        {
            foreach (var token in ExtractGlossaryTokens(line))
            {
                var normalized = NormalizeGlossaryToken(token);
                if (normalized == null) continue;
                if (!glossaryLookup.TryGetValue(normalized, out var nodes) || nodes.Count == 0)
                    missing.Add($"{token} -> {normalized}");
                else if (nodes.Count > 1)
                    ambiguous.Add(normalized);
            }
        }
    }

    if (missing.Count == 0 && ambiguous.Count == 0) return;

    var sb = new StringBuilder();
    sb.AppendLine("Glossary token validation failed:");
    if (missing.Count > 0)
    {
        sb.AppendLine(" Missing targets:");
        foreach (var entry in missing)
            sb.AppendLine($"  - {entry}");
    }
    if (ambiguous.Count > 0)
    {
        sb.AppendLine(" Ambiguous targets:");
        foreach (var entry in ambiguous)
            sb.AppendLine($"  - {entry}");
    }
    throw new InvalidOperationException(sb.ToString());
}

/// <summary>
/// Extract glossary tokens from a line in the form [[Token]].<br/>
/// Returns the raw token text without brackets.<br/>
/// </summary>
IEnumerable<string> ExtractGlossaryTokens(string line)
{
    const string TermStart = "[[";
    const string TermEnd = "]]";
    if (string.IsNullOrEmpty(line)) yield break;

    int idx = 0;
    while (true)
    {
        int start = line.IndexOf(TermStart, idx, StringComparison.Ordinal);
        if (start < 0) yield break;
        int end = line.IndexOf(TermEnd, start + TermStart.Length, StringComparison.Ordinal);
        if (end < 0) yield break;

        var term = line.Substring(start + TermStart.Length, end - (start + TermStart.Length));
        if (!string.IsNullOrWhiteSpace(term))
            yield return term;
        idx = end + TermEnd.Length;
        if (idx >= line.Length) yield break;
    }
}

/// <summary>
/// Normalize a glossary token for lookup, applying redirects and ignoring [[Zifika]].<br/>
/// Returns null when the token should be ignored.<br/>
/// </summary>
string NormalizeGlossaryToken(string token)
{
    if (string.IsNullOrWhiteSpace(token)) return null;
    if (string.Equals(token, "Zifika", StringComparison.OrdinalIgnoreCase)) return null;
    if (glossaryTokenRedirects.TryGetValue(token, out var redirect))
        return redirect;
    return token.Trim();
}

/// <summary>
/// Resolve a glossary node by its stripped title key, without redirects.<br/>
/// Throws if the key is ambiguous; returns null if missing.<br/>
/// </summary>
GlossaryNode ResolveGlossaryNodeKey(string key)
{
    var normalized = StripTermMarkup(key).Trim();
    if (string.IsNullOrWhiteSpace(normalized)) return null;
    if (!glossaryLookup.TryGetValue(normalized, out var nodes) || nodes.Count == 0)
        return null;
    if (nodes.Count > 1)
        throw new InvalidOperationException($"Glossary entry is ambiguous for key: {normalized}");
    return nodes[0];
}

/// <summary>
/// Build token jump items from a node's text block, preserving first-seen order.<br/>
/// Suppresses self-links and submenu duplicates.<br/>
/// </summary>
List<(string Label, GlossaryNode Target)> BuildTokenLinks(GlossaryNode node)
{
    var results = new List<(string Label, GlossaryNode Target)>();
    if (node == null || node.TextLines.Count == 0) return results;

    var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var child in node.Children)
    {
        if (!string.IsNullOrWhiteSpace(child.TitleKey))
            seenTargets.Add(child.TitleKey);
    }

    foreach (var line in node.TextLines)
    {
        foreach (var token in ExtractGlossaryTokens(line))
        {
            var normalized = NormalizeGlossaryToken(token);
            if (normalized == null) continue;
            var target = ResolveGlossaryNodeKey(normalized);
            if (target == null)
                throw new InvalidOperationException($"Glossary token '{token}' resolved to '{normalized}' but no matching node was found.");
            if (string.Equals(target.TitleKey, node.TitleKey, StringComparison.OrdinalIgnoreCase))
                continue;
            if (seenTargets.Add(target.TitleKey))
                results.Add(($"[[{token}]]", target));
        }
    }

    return results;
}

/// <summary>
/// Allocate menu letters for glossary items, skipping reserved keys.<br/>
/// Throws if the menu exceeds available letters at the current node.<br/>
/// </summary>
List<char> BuildGlossaryMenuLetters(int count, string contextKey)
{
    var letters = new List<char>();
    for (char c = 'A'; c <= 'Z'; c++)
    {
        if (c == 'T' || c == 'Y' || c == 'X') continue;
        letters.Add(c);
    }
    if (count > letters.Count)
        throw new InvalidOperationException($"Glossary menu too large at '{contextKey}' ({count} items).");
    return letters;
}

/// <summary>
/// Build a deterministic payload of the requested byte length using a repeating UTF-8 seed.<br/>
/// Keeps output reproducible while allowing "horrible" seed content to surface edge cases.<br/>
/// </summary>
byte[] BuildPatternPayload(int length, string seed)
{
    if (string.IsNullOrEmpty(seed)) throw new ArgumentException("Seed cannot be empty", nameof(seed));
    if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
    var seedBytes = Encoding.UTF8.GetBytes(seed);
    var data = new byte[length];
    for (int i = 0; i < length; i++)
        data[i] = seedBytes[i % seedBytes.Length];
    return data;
}

/// <summary>
/// Pre-canned plaintexts (no zero-length) mixing mundane and "horrible" control/ASCII patterns.<br/>
/// Lengths target 1,31,32,33,1024,4096,16384 bytes for quick eyeball and overhead checks.<br/>
/// </summary>
List<(string Label, byte[] Payload)> BuildPresetPayloads()
{
    return new List<(string, byte[])>
    {
        ("len-1-mundane", BuildPatternPayload(1, "A")),
        ("len-31-pangramish", BuildPatternPayload(31, "sphinx-of-black-quartz-judge")),
        ("len-32-repeater", BuildPatternPayload(32, "0123456789ABCDEF")),
        ("len-33-horrible", BuildPatternPayload(33, "ctrl-\u0001\u0002\u0003-~-\u007F-x")),
        ("len-1024-mixed", BuildPatternPayload(1024, "horrible-\u0001\u0002-\u0007-.-crypto-Zifika-vKey-")),
        ("len-4096-mundane", BuildPatternPayload(4096, "mundane-rows-cols-path-walk-")),
        ("len-16384-binaryish", BuildPatternPayload(16384, "bin-\u0000\u0001\u0002\u0003-\u001B-~-repeat-"))
    };
}

/// <summary>
/// Build a deterministic payload by repeating a caller-provided byte seed.<br/>
/// This overload avoids UTF-8 conversion so non-text byte patterns remain exact.<br/>
/// </summary>
/// <param name="length">Requested output length in bytes.<br/></param>
/// <param name="seed">Non-empty seed bytes repeated to fill output.<br/></param>
/// <returns>Deterministic byte array of requested length.<br/></returns>
byte[] BuildPatternPayloadBytes(int length, ReadOnlySpan<byte> seed)
{
    if (seed.IsEmpty) throw new ArgumentException("Seed cannot be empty", nameof(seed));
    if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
    var data = new byte[length];
    for (int i = 0; i < length; i++)
        data[i] = seed[i % seed.Length];
    return data;
}

/// <summary>
/// Build a deterministic payload fully filled with one byte value.<br/>
/// Used for non-typical all-zero/all-0xFF attack inputs.<br/>
/// </summary>
/// <param name="length">Requested output length in bytes.<br/></param>
/// <param name="value">Byte value to repeat.<br/></param>
/// <returns>Filled byte array of requested length.<br/></returns>
byte[] BuildFilledPayload(int length, byte value)
{
    if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
    var data = new byte[length];
    data.AsSpan().Fill(value);
    return data;
}

/// <summary>
/// Build attack-focused payloads that include both typical and non-typical byte distributions.<br/>
/// The set is intentionally small and deterministic so critics can reproduce outcomes quickly.<br/>
/// </summary>
/// <returns>Label/payload pairs for attack simulation runs.<br/></returns>
List<(string Label, byte[] Payload)> BuildAttackPayloads()
{
    return new List<(string, byte[])>
    {
        ("typical-plain-64", BuildPatternPayload(64, "the-quick-brown-fox-jumps-over-lazy-dog-")),
        ("typical-plain-1024", BuildPatternPayload(1024, "sane-user-input-path-walk-coverage-")),
        ("nontypical-len-1-zero", new byte[] { 0x00 }),
        ("nontypical-all-zero-128", BuildFilledPayload(128, 0x00)),
        ("nontypical-all-ff-128", BuildFilledPayload(128, 0xFF)),
        ("nontypical-repeater-257", BuildPatternPayload(257, "AAAAABBBBBCCCCCDDDDDEEEEE")),
        ("nontypical-binary-513", BuildPatternPayloadBytes(513, new byte[] { 0x00, 0x01, 0x02, 0x03, 0x1B, 0x7E, 0x7F, 0x80, 0xFF }))
    };
}

/// <summary>
/// Produce a stable 32-bit seed from text for deterministic fuzz mutation generation.<br/>
/// This avoids runtime-randomized string hash behavior so runs are reproducible.<br/>
/// </summary>
/// <param name="text">Input label text.<br/></param>
/// <returns>Deterministic signed 32-bit seed.<br/></returns>
int StableSeedFromLabel(string text)
{
    if (text == null) throw new ArgumentNullException(nameof(text));
    unchecked
    {
        int hash = (int)2166136261;
        for (int i = 0; i < text.Length; i++)
            hash = (hash ^ text[i]) * 16777619;
        return hash;
    }
}

/// <summary>
/// Clone ciphertext and flip one byte by XOR mask at a clamped index.<br/>
/// Indexes outside range are clamped so the mutation always applies when input is non-empty.<br/>
/// </summary>
/// <param name="src">Source byte array to mutate.<br/></param>
/// <param name="index">Target index before clamping.<br/></param>
/// <param name="mask">XOR bitmask to apply (defaults to 0x01).<br/></param>
/// <returns>Mutated clone (or empty clone when source is empty).<br/></returns>
byte[] MutateFlipByte(ReadOnlySpan<byte> src, int index, byte mask = 0x01)
{
    var dst = src.ToArray();
    if (dst.Length == 0) return dst;
    if (index < 0) index = 0;
    if (index >= dst.Length) index = dst.Length - 1;
    dst[index] ^= mask;
    return dst;
}

/// <summary>
/// Clone ciphertext and truncate tail bytes.<br/>
/// If trim exceeds length the result is empty.<br/>
/// </summary>
/// <param name="src">Source byte array to mutate.<br/></param>
/// <param name="trimBytes">Number of tail bytes to remove.<br/></param>
/// <returns>Truncated clone.<br/></returns>
byte[] MutateTruncate(ReadOnlySpan<byte> src, int trimBytes)
{
    if (trimBytes < 0) throw new ArgumentOutOfRangeException(nameof(trimBytes));
    int keep = src.Length - trimBytes;
    if (keep < 0) keep = 0;
    return src.Slice(0, keep).ToArray();
}

/// <summary>
/// Clone ciphertext and append caller-provided bytes.<br/>
/// Used to simulate trailing garbage and framing extension attacks.<br/>
/// </summary>
/// <param name="src">Source byte array to mutate.<br/></param>
/// <param name="tail">Bytes to append.<br/></param>
/// <returns>Extended clone.<br/></returns>
byte[] MutateAppend(ReadOnlySpan<byte> src, ReadOnlySpan<byte> tail)
{
    var dst = new byte[src.Length + tail.Length];
    src.CopyTo(dst);
    tail.CopyTo(dst.AsSpan(src.Length));
    return dst;
}

/// <summary>
/// Extract the mint/verify payload row-offset segment from a full wire buffer by tail slicing.<br/>
/// Assumes payload stream length equals plaintext length and (when enabled) a 32-byte integrity seal is the final segment.<br/>
/// Returns empty when the requested segment cannot be represented safely by the provided inputs.<br/>
/// </summary>
/// <param name="wire">Full mint/verify wire bytes.<br/></param>
/// <param name="plainLen">Expected plaintext length for the sample.<br/></param>
/// <param name="hasIntegritySeal">Whether a 32-byte seal is present at wire tail.<br/></param>
/// <returns>Payload row-offset bytes for stats probes.<br/></returns>
byte[] ExtractMintVerifyPayloadSegment(ReadOnlySpan<byte> wire, int plainLen, bool hasIntegritySeal)
{
    if (plainLen <= 0) return Array.Empty<byte>();
    int sealLen = hasIntegritySeal ? 32 : 0;
    if (wire.Length < plainLen + sealLen) return Array.Empty<byte>();
    int start = wire.Length - sealLen - plainLen;
    if (start < 0) return Array.Empty<byte>();
    return wire.Slice(start, plainLen).ToArray();
}

/// <summary>
/// Splice two ciphertexts by taking first half from A and second half from B.<br/>
/// This simulates cross-message grafting attacks that break transcript continuity.<br/>
/// </summary>
/// <param name="a">Primary ciphertext.<br/></param>
/// <param name="b">Peer ciphertext donor.<br/></param>
/// <returns>Spliced ciphertext clone.<br/></returns>
byte[] MutateSpliceHalf(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
{
    if (a.IsEmpty) return a.ToArray();
    if (b.IsEmpty) return a.ToArray();
    int split = a.Length / 2;
    int tailLen = b.Length - (b.Length / 2);
    var dst = new byte[split + tailLen];
    a.Slice(0, split).CopyTo(dst);
    b.Slice(b.Length / 2, tailLen).CopyTo(dst.AsSpan(split));
    return dst;
}

/// <summary>
/// Attempt symmetric decrypt on tampered ciphertext and classify outcome as blocked/garbled or unexpected accept.<br/>
/// "Blocked/garbled" means null result, exception, or plaintext mismatch against original.<br/>
/// </summary>
/// <param name="tampered">Tampered ciphertext bytes.<br/></param>
/// <param name="originalPlain">Original plaintext bytes for match check.<br/></param>
/// <param name="key">Symmetric key used for decryption.<br/></param>
/// <param name="requireIntegrity">Integrity requirement flag passed to decrypt.<br/></param>
/// <param name="outcome">Human-readable outcome detail for logging.<br/></param>
/// <returns>True when attack was blocked or produced garbled output; false on unexpected perfect recovery.<br/></returns>
bool IsSymmetricBlockedOrGarbled(byte[] tampered, ReadOnlySpan<byte> originalPlain, ZifikaKey key, bool requireIntegrity, out string outcome)
{
    try
    {
        using var dec = Zifika.Decrypt(new ZifikaBufferStream(tampered), key, requireIntegrity);
        if (dec == null)
        {
            outcome = "blocked(null)";
            return true;
        }
        var recovered = dec.ToArray();
        bool match = originalPlain.SequenceEqual(recovered);
        outcome = match ? $"unexpected-match(len:{recovered.Length})" : $"garbled(len:{recovered.Length})";
        return !match;
    }
    catch (Exception ex)
    {
        outcome = $"blocked(exception:{ex.GetType().Name})";
        return true;
    }
}

/// <summary>
/// Attempt verify/decrypt on tampered ciphertext and classify outcome as blocked/garbled or unexpected accept.<br/>
/// "Blocked/garbled" means null result, exception, or plaintext mismatch against original.<br/>
/// </summary>
/// <param name="tampered">Tampered ciphertext bytes.<br/></param>
/// <param name="originalPlain">Original plaintext bytes for match check.<br/></param>
/// <param name="verifier">Verifier key used for verify/decrypt.<br/></param>
/// <param name="requireIntegrity">Integrity requirement flag passed to verify/decrypt.<br/></param>
/// <param name="outcome">Human-readable outcome detail for logging.<br/></param>
/// <returns>True when attack was blocked or produced garbled output; false on unexpected perfect recovery.<br/></returns>
bool IsMintVerifyBlockedOrGarbled(byte[] tampered, ReadOnlySpan<byte> originalPlain, ZifikaVerifierKey verifier, bool requireIntegrity, out string outcome)
{
    try
    {
        using var dec = Zifika.VerifyAndDecrypt(new ZifikaBufferStream(tampered), verifier, requireIntegrity: requireIntegrity);
        if (dec == null)
        {
            outcome = "blocked(null)";
            return true;
        }
        var recovered = dec.ToArray();
        bool match = originalPlain.SequenceEqual(recovered);
        outcome = match ? $"unexpected-match(len:{recovered.Length})" : $"garbled(len:{recovered.Length})";
        return !match;
    }
    catch (Exception ex)
    {
        outcome = $"blocked(exception:{ex.GetType().Name})";
        return true;
    }
}

/// <summary>
/// Emit one attack result line in red so attack context is visually explicit in the console output.<br/>
/// Optional detail mode appends a ciphertext preview for reproducibility/debugging.<br/>
/// </summary>
/// <param name="mode">Mode label (e.g., "sym" or "m/v").<br/></param>
/// <param name="payloadLabel">Payload case label.<br/></param>
/// <param name="attackName">Attack case label.<br/></param>
/// <param name="blockedOrGarbled">Outcome classification flag.<br/></param>
/// <param name="outcome">Outcome detail text.<br/></param>
/// <param name="detail">Whether to print tampered ciphertext preview.<br/></param>
/// <param name="tampered">Tampered ciphertext bytes.<br/></param>
void PrintAttackLine(string mode, string payloadLabel, string attackName, bool blockedOrGarbled, string outcome, bool detail, ReadOnlySpan<byte> tampered)
{
    WriteLineColor(ConsoleColor.Red,
        $"[{mode}-attack][{payloadLabel}] {attackName}: blocked-or-garbled={blockedOrGarbled} ({outcome})");
    if (detail)
        WriteLineColor(ConsoleColor.Red, $"[{mode}-attack][{payloadLabel}] tampered: {HexWithLen(tampered, 32)}");
}

/// <summary>
/// Count set bits in one byte using Kernighan reduction.<br/>
/// Kept local to avoid extra dependencies while staying deterministic.<br/>
/// </summary>
/// <param name="value">Input byte to count.<br/></param>
/// <returns>Number of set bits (0..8).<br/></returns>
int CountBits(byte value)
{
    int count = 0;
    while (value != 0)
    {
        value = (byte)(value & (value - 1));
        count++;
    }
    return count;
}

/// <summary>
/// Compute Shannon entropy, chi-square, serial correlation, and bit-balance for one wire byte span.<br/>
/// Metrics are sample-local and intended for comparative analysis, not proof-level claims.<br/>
/// </summary>
/// <param name="data">Full wire bytes for one sample.<br/></param>
/// <returns>Tuple of entropy, chi-square, serial correlation, and ones-ratio.<br/></returns>
(double Entropy, double ChiSquare, double SerialCorrelation, double BitBalance) ComputeWireMetrics(ReadOnlySpan<byte> data)
{
    if (data.IsEmpty) return (0d, 0d, 0d, 0d);

    int[] freq = new int[256];
    double ones = 0;
    double sumX = 0;
    double sumY = 0;
    double sumXX = 0;
    double sumYY = 0;
    double sumXY = 0;
    int pairCount = 0;

    byte prev = 0;
    bool hasPrev = false;
    for (int i = 0; i < data.Length; i++)
    {
        byte b = data[i];
        freq[b]++;
        ones += CountBits(b);

        if (hasPrev)
        {
            sumX += prev;
            sumY += b;
            sumXX += prev * prev;
            sumYY += b * b;
            sumXY += prev * b;
            pairCount++;
        }
        prev = b;
        hasPrev = true;
    }

    double total = data.Length;
    double entropy = 0d;
    double expected = total / 256d;
    double chi = 0d;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            double p = freq[i] / total;
            entropy -= p * (Math.Log(p) / Math.Log(2));
        }
        double diff = freq[i] - expected;
        chi += (diff * diff) / expected;
    }

    double serial = 0d;
    if (pairCount > 1)
    {
        double n = pairCount;
        double num = n * sumXY - (sumX * sumY);
        double denLeft = n * sumXX - (sumX * sumX);
        double denRight = n * sumYY - (sumY * sumY);
        double den = Math.Sqrt(Math.Max(0d, denLeft * denRight));
        serial = den > 0 ? num / den : 0d;
    }

    double bitBalance = ones / (8d * total);
    return (entropy, chi, serial, bitBalance);
}

/// <summary>
/// Summarize a sequence of scalar values with mean/stddev/min/max.<br/>
/// Stddev is sample standard deviation (n-1 denominator) when n&gt;1.<br/>
/// </summary>
/// <param name="values">Sequence to summarize.<br/></param>
/// <returns>Tuple of mean, stddev, min, and max.<br/></returns>
(double Mean, double StdDev, double Min, double Max) Summarize(IReadOnlyList<double> values)
{
    if (values == null || values.Count == 0) return (0d, 0d, 0d, 0d);
    double sum = 0d;
    double sumSq = 0d;
    double min = double.PositiveInfinity;
    double max = double.NegativeInfinity;
    for (int i = 0; i < values.Count; i++)
    {
        double v = values[i];
        sum += v;
        sumSq += v * v;
        if (v < min) min = v;
        if (v > max) max = v;
    }
    double n = values.Count;
    double mean = sum / n;
    double variance = n > 1 ? Math.Max(0d, (sumSq - ((sum * sum) / n)) / (n - 1d)) : 0d;
    return (mean, Math.Sqrt(variance), min, max);
}

/// <summary>
/// Compute an inclusive linear-interpolated percentile from a scalar sample list.<br/>
/// p must be in [0,1]. Returns 0 for empty inputs.<br/>
/// </summary>
double Percentile(IReadOnlyList<double> values, double p)
{
    if (values == null || values.Count == 0) return 0d;
    if (p <= 0d)
    {
        double min = double.PositiveInfinity;
        for (int i = 0; i < values.Count; i++) if (values[i] < min) min = values[i];
        return min;
    }
    if (p >= 1d)
    {
        double max = double.NegativeInfinity;
        for (int i = 0; i < values.Count; i++) if (values[i] > max) max = values[i];
        return max;
    }

    var sorted = new double[values.Count];
    for (int i = 0; i < values.Count; i++) sorted[i] = values[i];
    Array.Sort(sorted);

    double rank = p * (sorted.Length - 1);
    int lo = (int)Math.Floor(rank);
    int hi = (int)Math.Ceiling(rank);
    if (lo == hi) return sorted[lo];
    double t = rank - lo;
    return sorted[lo] + ((sorted[hi] - sorted[lo]) * t);
}

/// <summary>
/// Compute Welch's t-statistic between two independent timing groups.<br/>
/// Returns 0 when groups are too small or variance is degenerate.<br/>
/// </summary>
/// <param name="groupA">Group A values.<br/></param>
/// <param name="groupB">Group B values.<br/></param>
/// <returns>Welch t-statistic.<br/></returns>
double ComputeWelchT(IReadOnlyList<double> groupA, IReadOnlyList<double> groupB)
{
    if (groupA == null || groupB == null || groupA.Count < 2 || groupB.Count < 2) return 0d;
    var sA = Summarize(groupA);
    var sB = Summarize(groupB);
    double nA = groupA.Count;
    double nB = groupB.Count;
    double varA = sA.StdDev * sA.StdDev;
    double varB = sB.StdDev * sB.StdDev;
    double den = Math.Sqrt((varA / nA) + (varB / nB));
    if (den <= 0d) return 0d;
    return (sA.Mean - sB.Mean) / den;
}

/// <summary>
/// Compute normalized Hamming distance between two byte spans with zero-padding on the shorter side.<br/>
/// This allows comparing full-wire outputs even when lengths diverge.<br/>
/// </summary>
/// <param name="a">First byte span.<br/></param>
/// <param name="b">Second byte span.<br/></param>
/// <returns>Bit-difference ratio in [0,1].<br/></returns>
double ComputeNormalizedBitDistance(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
{
    int maxLen = Math.Max(a.Length, b.Length);
    if (maxLen == 0) return 0d;
    int bitDiff = 0;
    for (int i = 0; i < maxLen; i++)
    {
        byte av = i < a.Length ? a[i] : (byte)0;
        byte bv = i < b.Length ? b[i] : (byte)0;
        bitDiff += CountBits((byte)(av ^ bv));
    }
    return bitDiff / (8d * maxLen);
}

/// <summary>
/// Build 16 deterministic bytes from an integer seed for key derivation convenience.<br/>
/// This seed only controls harness-generated randomness; core library RNG use remains internal.<br/>
/// </summary>
/// <param name="seed">Deterministic seed value.<br/></param>
/// <returns>16-byte seed buffer.<br/></returns>
byte[] BuildDeterministicSeedBytes(int seed)
{
    var rng = new Random(seed);
    var bytes = new byte[16];
    rng.NextBytes(bytes);
    return bytes;
}

/// <summary>
/// Create a deterministic analysis payload for one sample index with mixed structure and entropy patterns.<br/>
/// This keeps sample generation reproducible while covering both regular and irregular byte distributions.<br/>
/// </summary>
/// <param name="rng">Deterministic RNG for payload generation.<br/></param>
/// <param name="index">Sample index.<br/></param>
/// <returns>Payload bytes for analysis sample.<br/></returns>
byte[] BuildAnalysisPayload(Random rng, int index)
{
    int bucket = index % 6;
    if (bucket == 0) return BuildPatternPayload(1 + (index % 64), "analysis-text-");
    if (bucket == 1) return BuildPatternPayload(64 + (index % 193), "review-coverage-");
    if (bucket == 2) return BuildFilledPayload(96, 0x00);
    if (bucket == 3) return BuildFilledPayload(96, 0xFF);
    if (bucket == 4) return BuildPatternPayloadBytes(257, new byte[] { 0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, 0x1B, 0x20 });
    int len = rng.Next(1, 1025);
    var data = new byte[len];
    rng.NextBytes(data);
    return data;
}

/// <summary>
/// Parse an optional positive integer from console input, using default when blank/EOF.<br/>
/// Retries on invalid input until a valid value or blank is entered.<br/>
/// </summary>
/// <param name="prompt">Prompt shown to the user.<br/></param>
/// <param name="defaultValue">Default when blank/EOF.<br/></param>
/// <param name="min">Minimum accepted value (inclusive).<br/></param>
/// <param name="max">Maximum accepted value (inclusive).<br/></param>
/// <returns>Parsed value or default.<br/></returns>
int ReadOptionalPositiveInt(string prompt, int defaultValue, int min = 1, int max = int.MaxValue)
{
    while (true)
    {
        Console.Write(prompt);
        var raw = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(raw)) return defaultValue;
        if (int.TryParse(raw.Trim(), out int value) && value >= min && value <= max)
            return value;
        WriteLineColor(ConsoleColor.Red, $"Enter an integer in [{min},{max}] or blank for default ({defaultValue}).");
    }
}

/// <summary>
/// Parse an optional 32-bit integer seed from console input, using default when blank/EOF.<br/>
/// Retries on invalid input until a valid value or blank is entered.<br/>
/// </summary>
/// <param name="prompt">Prompt shown to the user.<br/></param>
/// <param name="defaultValue">Default when blank/EOF.<br/></param>
/// <returns>Parsed seed or default.<br/></returns>
int ReadOptionalSeedInt(string prompt, int defaultValue)
{
    while (true)
    {
        Console.Write(prompt);
        var raw = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(raw)) return defaultValue;
        if (int.TryParse(raw.Trim(), out int value))
            return value;
        WriteLineColor(ConsoleColor.Red, $"Enter a valid Int32 seed or blank for default ({defaultValue}).");
    }
}

/// <summary>
/// Resolve artifact output directory for CSV export, preferring TestHarness/artifacts from repo root.<br/>
/// Falls back to local artifacts/ when running from project-local working directories.<br/>
/// </summary>
/// <returns>Directory path that exists after return.<br/></returns>
string ResolveArtifactsDirectory()
{
    string dir = Directory.Exists("TestHarness") ? Path.Combine("TestHarness", "artifacts") : "artifacts";
    Directory.CreateDirectory(dir);
    return dir;
}

/// <summary>
/// Format numeric values using invariant culture for stable CSV output across locales.<br/>
/// </summary>
/// <param name="value">Number to format.<br/></param>
/// <returns>Invariant fixed-point string.<br/></returns>
string Fmt(double value) => value.ToString("F6", CultureInfo.InvariantCulture);

/// <summary>
/// Execute per-mode analysis with hard checks on full wire and metric probes over a selectable byte projection.<br/>
/// Caller supplies mode-specific delegates for encryption/decryption/tamper behavior.<br/>
/// </summary>
/// <param name="modeName">Mode label for output rows.<br/></param>
/// <param name="sampleCount">Number of samples to generate/analyze.<br/></param>
/// <param name="seed">Deterministic seed controlling harness-side payload/mutation generation.<br/></param>
/// <param name="encryptWire">Encrypt/mint delegate returning full wire bytes.<br/></param>
/// <param name="roundtripMatches">Roundtrip verification delegate.<br/></param>
/// <param name="tamperBlockedOrGarbled">Tamper evaluation delegate returning blocked/garbled and outcome text.<br/></param>
/// <param name="wrongKeyBlockedOrGarbled">Wrong-key/verifier acceptance delegate.<br/></param>
/// <param name="seedLabel">Optional label used to keep deterministic sample generation aligned across related modes.<br/></param>
/// <param name="metricBytesSelector">Optional projection that selects which bytes are scored by statistical probes; defaults to full wire.<br/></param>
/// <param name="sampleRows">CSV row sink for per-sample records.<br/></param>
/// <returns>Mode analysis summary.<br/></returns>
AnalysisModeResult RunModeAnalysisCore(
    string modeName,
    int sampleCount,
    int seed,
    Func<byte[], byte[]> encryptWire,
    Func<byte[], byte[], bool> roundtripMatches,
    Func<byte[], byte[], (bool blockedOrGarbled, string outcome)> tamperBlockedOrGarbled,
    Func<byte[], byte[], bool> wrongKeyBlockedOrGarbled,
    string seedLabel,
    Func<byte[], byte[], byte[]> metricBytesSelector,
    List<string> sampleRows)
{
    static void WriteProgress(string mode, int done, int total)
    {
        if (total <= 0) return;
        const int width = 30;
        double ratio = Math.Clamp(done / (double)total, 0d, 1d);
        int fill = (int)Math.Round(width * ratio);
        if (fill < 0) fill = 0;
        if (fill > width) fill = width;
        string bar = new string('#', fill) + new string('-', width - fill);
        Console.Write($"\r[analysis][{mode}] [{bar}] {done}/{total}");
        if (done >= total) Console.WriteLine();
    }
    static void WritePhase(string mode, string phase)
    {
        Console.WriteLine($"[analysis][{mode}] phase: {phase}");
    }

    string effectiveSeedLabel = string.IsNullOrWhiteSpace(seedLabel) ? modeName : seedLabel;
    var rng = new Random(seed ^ StableSeedFromLabel("analysis-" + effectiveSeedLabel));
    var freq = new long[256];
    long totalBytes = 0;
    long onesTotal = 0;
    double pairSumX = 0d;
    double pairSumY = 0d;
    double pairSumXX = 0d;
    double pairSumYY = 0d;
    double pairSumXY = 0d;
    long pairCount = 0;
    var wireLengths = new List<double>(sampleCount);
    var avalancheSamples = new List<double>(Math.Min(sampleCount, 2000));

    int roundtripTotal = 0;
    int roundtripPassed = 0;
    int tamperTotal = 0;
    int tamperPassed = 0;
    int wrongKeyTotal = 0;
    int wrongKeyPassed = 0;
    byte[] firstPlain = null;
    byte[] firstWire = null;
    int progressTick = Math.Max(1, sampleCount / 100);

    WriteProgress(modeName, 0, sampleCount);

    for (int i = 0; i < sampleCount; i++)
    {
        var plain = BuildAnalysisPayload(rng, i);
        var wire = encryptWire(plain);
        if (firstWire == null)
        {
            firstPlain = plain;
            firstWire = wire;
        }

        var metricBytes = metricBytesSelector != null ? metricBytesSelector(wire, plain) : wire;
        metricBytes ??= Array.Empty<byte>();
        var wm = ComputeWireMetrics(metricBytes);
        wireLengths.Add(metricBytes.Length);

        for (int b = 0; b < metricBytes.Length; b++)
        {
            byte val = metricBytes[b];
            freq[val]++;
            totalBytes++;
            onesTotal += CountBits(val);

            if (b > 0)
            {
                byte prev = metricBytes[b - 1];
                pairSumX += prev;
                pairSumY += val;
                pairSumXX += prev * prev;
                pairSumYY += val * val;
                pairSumXY += prev * val;
                pairCount++;
            }
        }

        bool roundtripOk = roundtripMatches(wire, plain);
        roundtripTotal++;
        if (roundtripOk) roundtripPassed++;

        int tamperIndex = wire.Length == 0 ? 0 : ((i * 131) % wire.Length);
        var tampered = MutateFlipByte(wire, tamperIndex, (byte)(1 << (i % 8)));
        var tamperEval = tamperBlockedOrGarbled(tampered, plain);
        bool tamperOk = tamperEval.blockedOrGarbled;
        tamperTotal++;
        if (tamperOk) tamperPassed++;

        sampleRows.Add(string.Join(",",
            modeName,
            i.ToString(CultureInfo.InvariantCulture),
            plain.Length.ToString(CultureInfo.InvariantCulture),
            wire.Length.ToString(CultureInfo.InvariantCulture),
            metricBytes.Length.ToString(CultureInfo.InvariantCulture),
            Fmt(wm.Entropy),
            Fmt(wm.ChiSquare),
            Fmt(wm.SerialCorrelation),
            tamperIndex.ToString(CultureInfo.InvariantCulture),
            tamperEval.outcome ?? string.Empty,
            roundtripOk ? "1" : "0",
            tamperOk ? "1" : "0"));

        int done = i + 1;
        if (done == sampleCount || (done % progressTick) == 0)
            WriteProgress(modeName, done, sampleCount);
    }

    if (firstWire != null && firstPlain != null)
    {
        WritePhase(modeName, "wrong-key check");
        wrongKeyTotal++;
        bool wrongKeyOk = wrongKeyBlockedOrGarbled(firstWire, firstPlain);
        if (wrongKeyOk) wrongKeyPassed++;
    }

    WritePhase(modeName, "avalanche");
    int avalancheCount = Math.Min(sampleCount, 2000);
    var rngAval = new Random(seed ^ StableSeedFromLabel("avalanche-" + effectiveSeedLabel));
    int avalancheTick = Math.Max(1, avalancheCount / 100);
    WriteProgress(modeName + " avalanche", 0, avalancheCount);
    for (int i = 0; i < avalancheCount; i++)
    {
        var plain = BuildAnalysisPayload(rngAval, i + 100_000);
        var mutated = (byte[])plain.Clone();
        int idx = i % mutated.Length;
        mutated[idx] ^= (byte)(1 << (i % 8));
        var wireA = encryptWire(plain);
        var wireB = encryptWire(mutated);
        var metricA = metricBytesSelector != null ? metricBytesSelector(wireA, plain) : wireA;
        var metricB = metricBytesSelector != null ? metricBytesSelector(wireB, mutated) : wireB;
        metricA ??= Array.Empty<byte>();
        metricB ??= Array.Empty<byte>();
        avalancheSamples.Add(ComputeNormalizedBitDistance(metricA, metricB));
        int done = i + 1;
        if (done == avalancheCount || (done % avalancheTick) == 0)
            WriteProgress(modeName + " avalanche", done, avalancheCount);
    }

    WritePhase(modeName, "distinguisher");
    int distinguisherCount = Math.Max(40, Math.Min(sampleCount, 4000));
    if ((distinguisherCount & 1) != 0) distinguisherCount++;
    double[] f0 = new double[distinguisherCount];
    double[] f1 = new double[distinguisherCount];
    var rngDist = new Random(seed ^ StableSeedFromLabel("distinguisher-" + effectiveSeedLabel));
    int distTick = Math.Max(1, distinguisherCount / 100);
    WriteProgress(modeName + " distinguisher", 0, distinguisherCount);
    for (int i = 0; i < distinguisherCount; i++)
    {
        var p0 = BuildFilledPayload(128, 0x00);
        var p1 = new byte[128];
        rngDist.NextBytes(p1);
        var w0 = encryptWire(p0);
        var w1 = encryptWire(p1);
        var m0 = metricBytesSelector != null ? metricBytesSelector(w0, p0) : w0;
        var m1 = metricBytesSelector != null ? metricBytesSelector(w1, p1) : w1;
        m0 ??= Array.Empty<byte>();
        m1 ??= Array.Empty<byte>();
        int t0 = Math.Min(16, m0.Length);
        int t1 = Math.Min(16, m1.Length);
        double s0 = 0d;
        double s1 = 0d;
        for (int j = 0; j < t0; j++) s0 += m0[j];
        for (int j = 0; j < t1; j++) s1 += m1[j];
        f0[i] = t0 > 0 ? s0 / t0 : 0d;
        f1[i] = t1 > 0 ? s1 / t1 : 0d;
        int done = i + 1;
        if (done == distinguisherCount || (done % distTick) == 0)
            WriteProgress(modeName + " distinguisher", done, distinguisherCount);
    }
    int split = distinguisherCount / 2;
    double mean0 = 0d;
    double mean1 = 0d;
    for (int i = 0; i < split; i++)
    {
        mean0 += f0[i];
        mean1 += f1[i];
    }
    mean0 /= split;
    mean1 /= split;
    int correct = 0;
    int totalPred = 0;
    for (int i = split; i < distinguisherCount; i++)
    {
        int pred0 = Math.Abs(f0[i] - mean0) <= Math.Abs(f0[i] - mean1) ? 0 : 1;
        int pred1 = Math.Abs(f1[i] - mean0) <= Math.Abs(f1[i] - mean1) ? 0 : 1;
        if (pred0 == 0) correct++;
        if (pred1 == 1) correct++;
        totalPred += 2;
    }
    double distinguisherAccuracy = totalPred > 0 ? correct / (double)totalPred : 0d;

    WritePhase(modeName, "timing");
    int timingCount = Math.Max(100, Math.Min(sampleCount, 2000));
    var rngTiming = new Random(seed ^ StableSeedFromLabel("timing-" + effectiveSeedLabel));
    var tGroupA = new List<double>(timingCount);
    var tGroupB = new List<double>(timingCount);
    int timingTick = Math.Max(1, timingCount / 100);
    WriteProgress(modeName + " timing", 0, timingCount);
    for (int i = 0; i < timingCount; i++)
    {
        var pA = BuildFilledPayload(256, 0x00);
        var pB = new byte[256];
        rngTiming.NextBytes(pB);

        long sA = Stopwatch.GetTimestamp();
        var _wa = encryptWire(pA);
        long eA = Stopwatch.GetTimestamp();
        tGroupA.Add((double)(eA - sA));

        long sB = Stopwatch.GetTimestamp();
        var _wb = encryptWire(pB);
        long eB = Stopwatch.GetTimestamp();
        tGroupB.Add((double)(eB - sB));
        int done = i + 1;
        if (done == timingCount || (done % timingTick) == 0)
            WriteProgress(modeName + " timing", done, timingCount);
    }
    double timingT = ComputeWelchT(tGroupA, tGroupB);

    double entropyGlobal = 0d;
    double chiGlobal = 0d;
    if (totalBytes > 0)
    {
        double expected = totalBytes / 256d;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] > 0)
            {
                double p = freq[i] / (double)totalBytes;
                entropyGlobal -= p * (Math.Log(p) / Math.Log(2));
            }
            double diff = freq[i] - expected;
            chiGlobal += (diff * diff) / expected;
        }
    }

    double serialGlobal = 0d;
    if (pairCount > 1)
    {
        double n = pairCount;
        double num = n * pairSumXY - (pairSumX * pairSumY);
        double denLeft = n * pairSumXX - (pairSumX * pairSumX);
        double denRight = n * pairSumYY - (pairSumY * pairSumY);
        double den = Math.Sqrt(Math.Max(0d, denLeft * denRight));
        serialGlobal = den > 0 ? num / den : 0d;
    }

    double bitBalanceGlobal = totalBytes > 0 ? onesTotal / (8d * totalBytes) : 0d;
    var wireLenStats = Summarize(wireLengths);
    var avalancheStats = Summarize(avalancheSamples);
    double avalancheP05 = Percentile(avalancheSamples, 0.05);
    double avalancheP50 = Percentile(avalancheSamples, 0.50);
    double avalancheP95 = Percentile(avalancheSamples, 0.95);

    var flags = new List<string>();
    bool isMvWire = modeName.IndexOf("mint-verify-wire", StringComparison.OrdinalIgnoreCase) >= 0;

    // Entropy near 8.0 is desirable; only flag low entropy.
    if (entropyGlobal < 7.90) flags.Add("entropy");

    // Chi-square thresholds are view-specific:
    // - mint-verify-wire includes structured protocol fields, so chi is informational only (no flag).
    // - payload/symmetric keep broad guard rails to catch strong regressions.
    if (!isMvWire)
    {
        double chiMin = 120.0;
        double chiMax = 5000.0;
        if (chiGlobal < chiMin || chiGlobal > chiMax) flags.Add("chi");
    }

    if (Math.Abs(serialGlobal) > 0.12) flags.Add("serial");
    if (Math.Abs(bitBalanceGlobal - 0.5) > 0.02) flags.Add("bit-balance");
    if (avalancheStats.Mean < 0.35 || avalancheStats.Mean > 0.65) flags.Add("avalanche");
    if (distinguisherAccuracy > 0.56) flags.Add("distinguisher");
    if (Math.Abs(timingT) > 5.0) flags.Add("timing");
    WritePhase(modeName, "finalizing");

    return new AnalysisModeResult
    {
        Mode = modeName,
        SampleCount = sampleCount,
        TotalBytes = totalBytes,
        RoundtripPassed = roundtripPassed,
        RoundtripTotal = roundtripTotal,
        TamperBlockedPassed = tamperPassed,
        TamperBlockedTotal = tamperTotal,
        WrongKeyBlockedPassed = wrongKeyPassed,
        WrongKeyBlockedTotal = wrongKeyTotal,
        HardChecksPassed = roundtripPassed + tamperPassed + wrongKeyPassed,
        HardChecksTotal = roundtripTotal + tamperTotal + wrongKeyTotal,
        EntropyGlobal = entropyGlobal,
        ChiSquareGlobal = chiGlobal,
        SerialCorrelationGlobal = serialGlobal,
        BitBalanceGlobal = bitBalanceGlobal,
        WireLengthMean = wireLenStats.Mean,
        WireLengthStdDev = wireLenStats.StdDev,
        AvalancheMean = avalancheStats.Mean,
        AvalancheStdDev = avalancheStats.StdDev,
        AvalancheMin = avalancheStats.Min,
        AvalancheMax = avalancheStats.Max,
        AvalancheP05 = avalancheP05,
        AvalancheP50 = avalancheP50,
        AvalancheP95 = avalancheP95,
        DistinguisherAccuracy = distinguisherAccuracy,
        TimingTStatistic = timingT,
        StatisticalFlags = flags
    };
}

/// <summary>
/// Print one mode summary with hard pass/fail and statistical metric flags.<br/>
/// Intended as a reviewer-facing baseline snapshot before independent analysis work.<br/>
/// </summary>
/// <param name="result">Mode analysis result summary.<br/></param>
void PrintModeAnalysisSummary(AnalysisModeResult result)
{
    bool roundtripPass = result.RoundtripPassed == result.RoundtripTotal;
    bool tamperPass = result.TamperBlockedPassed == result.TamperBlockedTotal;
    bool wrongKeyPass = result.WrongKeyBlockedPassed == result.WrongKeyBlockedTotal;
    bool hardPass = result.HardChecksPassed == result.HardChecksTotal;
    bool statsPass = result.StatisticalFlags.Count == 0;
    WriteLineColor(ConsoleColor.Cyan, $"[analysis][{result.Mode}] samples={result.SampleCount} totalMetricBytes={result.TotalBytes}");
    WriteLineColor(roundtripPass ? ConsoleColor.Green : ConsoleColor.Red,
        $"[analysis][{result.Mode}] roundtrip-checks: {result.RoundtripPassed}/{result.RoundtripTotal} {(roundtripPass ? "PASS" : "FAIL")}");
    WriteLineColor(tamperPass ? ConsoleColor.Green : ConsoleColor.Red,
        $"[analysis][{result.Mode}] tamper-checks: {result.TamperBlockedPassed}/{result.TamperBlockedTotal} {(tamperPass ? "PASS" : "FAIL")}");
    WriteLineColor(wrongKeyPass ? ConsoleColor.Green : ConsoleColor.Red,
        $"[analysis][{result.Mode}] wrong-key-checks: {result.WrongKeyBlockedPassed}/{result.WrongKeyBlockedTotal} {(wrongKeyPass ? "PASS" : "FAIL")}");
    WriteLineColor(hardPass ? ConsoleColor.Green : ConsoleColor.Red,
        $"[analysis][{result.Mode}] hard-checks: {result.HardChecksPassed}/{result.HardChecksTotal} {(hardPass ? "PASS" : "FAIL")}");
    if (!string.IsNullOrWhiteSpace(result.HardChecksInheritedFrom))
        Console.WriteLine($"[analysis][{result.Mode}] hard-check-source: inherited-from={result.HardChecksInheritedFrom}");
    WriteLineColor(statsPass ? ConsoleColor.Green : ConsoleColor.Red,
        $"[analysis][{result.Mode}] statistical-flags: {(statsPass ? "none" : string.Join("|", result.StatisticalFlags))}");
    Console.WriteLine($"[analysis][{result.Mode}] entropy={Fmt(result.EntropyGlobal)} chi={Fmt(result.ChiSquareGlobal)} serial={Fmt(result.SerialCorrelationGlobal)} bitBalance={Fmt(result.BitBalanceGlobal)}");
    Console.WriteLine($"[analysis][{result.Mode}] wireLenMean={Fmt(result.WireLengthMean)} wireLenStd={Fmt(result.WireLengthStdDev)}");
    Console.WriteLine($"[analysis][{result.Mode}] avalancheMean={Fmt(result.AvalancheMean)} avalancheStd={Fmt(result.AvalancheStdDev)} range=[{Fmt(result.AvalancheMin)},{Fmt(result.AvalancheMax)}] p05={Fmt(result.AvalancheP05)} p50={Fmt(result.AvalancheP50)} p95={Fmt(result.AvalancheP95)}");
    Console.WriteLine($"[analysis][{result.Mode}] distinguisherAccuracy={Fmt(result.DistinguisherAccuracy)} timingWelchT={Fmt(result.TimingTStatistic)}");
}

/// <summary>
/// Run analysis suite for symmetric plus mint/verify wire/payload views, then export sample/summary CSV artifacts.<br/>
/// Seed controls harness-generated payloads/mutations for reproducible sampling.<br/>
/// </summary>
/// <param name="profileLabel">Profile label (quick/deep/custom).<br/></param>
/// <param name="sampleCount">Requested sample count.<br/></param>
/// <param name="seed">Harness deterministic seed.<br/></param>
void RunAnalysisSuite(string profileLabel, int sampleCount, int seed)
{
    WriteLineColor(ConsoleColor.Cyan, $"=== Analysis ({profileLabel}) ===");
    Console.WriteLine($" seed(harness)={seed} sampleCount={sampleCount}");
    Console.WriteLine(" note: seed controls harness payload/mutation generation; core library internal RNG remains internal.");

    var sampleRows = new List<string>
    {
        "mode,sample_idx,plain_len,wire_len,metric_len,sample_entropy,sample_chi,sample_serial,tamper_index,tamper_outcome,roundtrip_ok,tamper_blocked"
    };

    bool oldMintDebug = Zifika.DebugMintVerify;
    Zifika.DebugMintVerify = false;
    try
    {
        var symSeedMain = BuildDeterministicSeedBytes(seed ^ 0x13572468);
        var symSeedWrong = BuildDeterministicSeedBytes(seed ^ unchecked((int)0x89ABCDEF));
        using var symKey = Zifika.CreateKey(symSeedMain, keySize: 8);
        using var symWrong = Zifika.CreateKey(symSeedWrong, keySize: 8);
        AnalysisModeResult symResult = RunModeAnalysisCore(
            "symmetric",
            sampleCount,
            seed ^ StableSeedFromLabel("sym-core"),
            plain =>
            {
                using var ct = Zifika.Encrypt(plain, symKey, useIntegrity: true);
                return ct.ToArray();
            },
            (wire, plain) =>
            {
                using var dec = Zifika.Decrypt(new ZifikaBufferStream(wire), symKey, requireIntegrity: true);
                return dec != null && plain.AsSpan().SequenceEqual(dec.AsReadOnlySpan);
            },
            (wire, plain) =>
            {
                bool ok = IsSymmetricBlockedOrGarbled(wire, plain, symKey, true, out string outcome);
                return (ok, outcome);
            },
            (wire, plain) => IsSymmetricBlockedOrGarbled(wire, plain, symWrong, true, out _),
            "symmetric",
            null,
            sampleRows);

        var mainPair = Zifika.CreateMintingKeyPair();
        var wrongPair = Zifika.CreateMintingKeyPair();
        AnalysisModeResult mvWireResult = RunModeAnalysisCore(
            "mint-verify-wire",
            sampleCount,
            seed ^ StableSeedFromLabel("mv-core"),
            plain =>
            {
                using var ct = Zifika.Mint(plain, mainPair.minting, useIntegrity: true);
                return ct.ToArray();
            },
            (wire, plain) =>
            {
                using var dec = Zifika.VerifyAndDecrypt(new ZifikaBufferStream(wire), mainPair.verifier, requireIntegrity: true);
                return dec != null && plain.AsSpan().SequenceEqual(dec.AsReadOnlySpan);
            },
            (wire, plain) =>
            {
                bool ok = IsMintVerifyBlockedOrGarbled(wire, plain, mainPair.verifier, true, out string outcome);
                return (ok, outcome);
            },
            (wire, plain) => IsMintVerifyBlockedOrGarbled(wire, plain, wrongPair.verifier, true, out _),
            "mint-verify",
            null,
            sampleRows);

        AnalysisModeResult mvPayloadResult = RunModeAnalysisCore(
            "mint-verify-payload",
            sampleCount,
            seed ^ StableSeedFromLabel("mv-core"),
            plain =>
            {
                using var ct = Zifika.Mint(plain, mainPair.minting, useIntegrity: true);
                return ct.ToArray();
            },
            (wire, plain) =>
            {
                using var dec = Zifika.VerifyAndDecrypt(new ZifikaBufferStream(wire), mainPair.verifier, requireIntegrity: true);
                return dec != null && plain.AsSpan().SequenceEqual(dec.AsReadOnlySpan);
            },
            (wire, plain) =>
            {
                bool ok = IsMintVerifyBlockedOrGarbled(wire, plain, mainPair.verifier, true, out string outcome);
                return (ok, outcome);
            },
            (wire, plain) => IsMintVerifyBlockedOrGarbled(wire, plain, wrongPair.verifier, true, out _),
            "mint-verify",
            (wire, plain) => ExtractMintVerifyPayloadSegment(wire, plain.Length, hasIntegritySeal: true),
            sampleRows);

        // Payload view is a statistical lens over the same mode, not an independent hard-check gate.
        // Inherit hard-check outcomes from the mint-verify wire run to avoid independent RNG noise.
        mvPayloadResult.RoundtripPassed = mvWireResult.RoundtripPassed;
        mvPayloadResult.RoundtripTotal = mvWireResult.RoundtripTotal;
        mvPayloadResult.TamperBlockedPassed = mvWireResult.TamperBlockedPassed;
        mvPayloadResult.TamperBlockedTotal = mvWireResult.TamperBlockedTotal;
        mvPayloadResult.WrongKeyBlockedPassed = mvWireResult.WrongKeyBlockedPassed;
        mvPayloadResult.WrongKeyBlockedTotal = mvWireResult.WrongKeyBlockedTotal;
        mvPayloadResult.HardChecksPassed = mvWireResult.HardChecksPassed;
        mvPayloadResult.HardChecksTotal = mvWireResult.HardChecksTotal;
        mvPayloadResult.HardChecksInheritedFrom = mvWireResult.Mode;

        PrintModeAnalysisSummary(symResult);
        PrintModeAnalysisSummary(mvWireResult);
        PrintModeAnalysisSummary(mvPayloadResult);

        string artifactsDir = ResolveArtifactsDirectory();
        string stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        string profileSlug = profileLabel.Replace(' ', '-').ToLowerInvariant();
        string samplePath = Path.Combine(artifactsDir, $"analysis_samples_{profileSlug}_{stamp}.csv");
        string summaryPath = Path.Combine(artifactsDir, $"analysis_summary_{profileSlug}_{stamp}.csv");

        File.WriteAllLines(samplePath, sampleRows);
        var summaryRows = new List<string>
        {
            "mode,sample_count,total_metric_bytes,roundtrip_passed,roundtrip_total,tamper_passed,tamper_total,wrong_key_passed,wrong_key_total,hard_passed,hard_total,entropy_global,chi_global,serial_global,bit_balance_global,metric_len_mean,metric_len_std,avalanche_mean,avalanche_std,avalanche_min,avalanche_max,avalanche_p05,avalanche_p50,avalanche_p95,distinguisher_accuracy,timing_welch_t,stat_flags"
        };
        void AddSummaryRow(AnalysisModeResult r)
        {
            summaryRows.Add(string.Join(",",
                r.Mode,
                r.SampleCount.ToString(CultureInfo.InvariantCulture),
                r.TotalBytes.ToString(CultureInfo.InvariantCulture),
                r.RoundtripPassed.ToString(CultureInfo.InvariantCulture),
                r.RoundtripTotal.ToString(CultureInfo.InvariantCulture),
                r.TamperBlockedPassed.ToString(CultureInfo.InvariantCulture),
                r.TamperBlockedTotal.ToString(CultureInfo.InvariantCulture),
                r.WrongKeyBlockedPassed.ToString(CultureInfo.InvariantCulture),
                r.WrongKeyBlockedTotal.ToString(CultureInfo.InvariantCulture),
                r.HardChecksPassed.ToString(CultureInfo.InvariantCulture),
                r.HardChecksTotal.ToString(CultureInfo.InvariantCulture),
                Fmt(r.EntropyGlobal),
                Fmt(r.ChiSquareGlobal),
                Fmt(r.SerialCorrelationGlobal),
                Fmt(r.BitBalanceGlobal),
                Fmt(r.WireLengthMean),
                Fmt(r.WireLengthStdDev),
                Fmt(r.AvalancheMean),
                Fmt(r.AvalancheStdDev),
                Fmt(r.AvalancheMin),
                Fmt(r.AvalancheMax),
                Fmt(r.AvalancheP05),
                Fmt(r.AvalancheP50),
                Fmt(r.AvalancheP95),
                Fmt(r.DistinguisherAccuracy),
                Fmt(r.TimingTStatistic),
                r.StatisticalFlags.Count == 0 ? "none" : string.Join("|", r.StatisticalFlags)));
        }
        AddSummaryRow(symResult);
        AddSummaryRow(mvWireResult);
        AddSummaryRow(mvPayloadResult);
        File.WriteAllLines(summaryPath, summaryRows);

        WriteLineColor(ConsoleColor.Yellow, $"[analysis] samples csv: {samplePath}");
        WriteLineColor(ConsoleColor.Yellow, $"[analysis] summary csv: {summaryPath}");
        Console.WriteLine();
    }
    finally
    {
        Zifika.DebugMintVerify = oldMintDebug;
    }
}

/// <summary>
/// Analysis menu with Quick/Deep profiles and optional overrides for sample count and deterministic harness seed.<br/>
/// Outputs hard pass/fail and statistical metric flags plus CSV artifacts for external review.<br/>
/// </summary>
void RunAnalysisMenu()
{
    breadcrumb = new List<string> { "Main", "Analysis" };
    const int quickDefault = 1000;
    const int deepDefault = 20000;
    int quickSeedDefault = StableSeedFromLabel("analysis-quick-v1");
    int deepSeedDefault = StableSeedFromLabel("analysis-deep-v1");

    while (true)
    {
        Console.WriteLine();
        PrintBreadcrumb();
        WriteLineColor(ConsoleColor.Cyan, "Analysis menu:");
        Console.WriteLine($"  A) Quick profile (default samples:{quickDefault})");
        Console.WriteLine($"  B) Deep profile (default samples:{deepDefault})");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A/B/X or ESC): ", "A", "B", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;

        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
        {
            int count = ReadOptionalPositiveInt($"Sample count (blank={quickDefault}): ", quickDefault, 1, 500000);
            int seed = ReadOptionalSeedInt($"Harness seed (Int32, blank={quickSeedDefault}): ", quickSeedDefault);
            RunAnalysisSuite("quick", count, seed);
            continue;
        }

        if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            int count = ReadOptionalPositiveInt($"Sample count (blank={deepDefault}): ", deepDefault, 1, 500000);
            int seed = ReadOptionalSeedInt($"Harness seed (Int32, blank={deepSeedDefault}): ", deepSeedDefault);
            RunAnalysisSuite("deep", count, seed);
            continue;
        }
    }
}

/// <summary>
/// Render a hex preview with length tag and optional truncation for large buffers.<br/>
/// </summary>
string HexWithLen(ReadOnlySpan<byte> data, int previewBytes = 64)
{
    int show = Math.Min(data.Length, previewBytes);
    var hex = Convert.ToHexString(data.Slice(0, show));
    var suffix = data.Length > previewBytes ? "..." : string.Empty;
    return $"[len:{data.Length}] {hex}{suffix}";
}

/// <summary>
/// Render a UTF-8 view with length tag, control char escaping, and truncation for readability.<br/>
/// </summary>
string Utf8WithLen(ReadOnlySpan<byte> data, int maxChars = 120)
{
    var raw = Encoding.UTF8.GetString(data);
    var sb = new StringBuilder();
    foreach (char ch in raw)
    {
        if (ch == '\r') sb.Append("\\r");
        else if (ch == '\n') sb.Append("\\n");
        else if (char.IsControl(ch)) sb.Append('.');
        else sb.Append(ch);

        if (sb.Length >= maxChars)
        {
            sb.Append("...");
            break;
        }
    }
    return $"[len:{data.Length}] {sb}";
}

/// <summary>
/// Prompt for required input but allow cancel with 0/empty/EOF; returns null on cancel.<br/>
/// </summary>
string ReadRequiredCancelable(string prompt)
{
    while (true)
    {
        Console.Write(prompt);
        var raw = Console.ReadLine();
        if (raw == null) return null;
        var input = raw.Trim();
        if (string.IsNullOrEmpty(input)) return null; // blank = cancel
        return input;
    }
}

/// <summary>
/// Prompt for a single keypress choice (no Enter required); case-insensitive match to allowed options.<br/>
/// ESC always returns "ESC" so callers can treat it as back/cancel even if not listed in allowed.<br/>
/// Echoes the pressed key for feedback; retries on invalid input.<br/>
/// </summary>
string ReadChoiceKey(string prompt, params string[] allowed)
{
    while (true)
    {
        Console.Write(prompt);
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Escape)
        {
            Console.WriteLine("[ESC]");
            return "ESC";
        }
        var s = key.KeyChar.ToString();
        Console.WriteLine(s);
        foreach (var option in allowed)
        {
            if (string.Equals(s, option, StringComparison.OrdinalIgnoreCase))
                return option;
        }
        Console.WriteLine($"Choose one of: {string.Join("/", allowed)} or ESC");
    }
}

/// <summary>
/// Prompt for hex input and return decoded bytes; loops until valid hex is provided.<br/>
/// </summary>
byte[] ReadHexBytes(string prompt)
{
    while (true)
    {
        if (TryGetClipboardHex(out var cbBytes, out var cbHex))
        {
            Console.WriteLine($" Clipboard hex detected [{cbBytes.Length} bytes]; press Enter to use it, or type anything else to enter manually.");
            var line = Console.ReadLine();
            if (string.IsNullOrEmpty(line))
                return cbBytes;
        }

        var input = ReadRequiredCancelable(prompt + " (blank to cancel): ");
        if (input == null) return null;
        var normalized = NormalizeHex(input);
        if (normalized == null)
        {
            Console.WriteLine("Invalid hex. Please try again (remove separators, ensure even length).");
            continue;
        }
        return normalized;
    }
}

/// <summary>
/// Prompt for payload bytes as UTF-8 text or hex; caller supplies context label (e.g. plaintext/ciphertext).<br/>
/// </summary>
byte[]? PromptPayloadBytes(string label)
{
    Console.WriteLine();
    PrintBreadcrumb(BuildBreadcrumbPath($"Input ({label})"));
    Console.WriteLine($"{label}: choose input type");
    Console.WriteLine("  A) UTF-8 text");
    Console.WriteLine("  B) Hex");
    bool cbHexAvailable = TryGetClipboardHex(out var cbBytes, out var cbHex);
    if (cbHexAvailable) Console.WriteLine("  C) Hex from clipboard");
    Console.WriteLine("  X) Back (ESC)");
    var allowed = cbHexAvailable ? new[] { "A", "B", "C", "X" } : new[] { "A", "B", "X" };
    var choice = ReadChoiceKey($"Select ({string.Join("/", allowed)} or ESC): ", allowed);
    if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return null;
    if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
    {
        var text = ReadRequiredCancelable($"Enter {label} (UTF-8, blank to cancel): ");
        return text == null ? null : Encoding.UTF8.GetBytes(text);
    }
    if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase) && cbHexAvailable)
    {
        Console.WriteLine($" Using clipboard hex [{cbBytes.Length} bytes].");
        return cbBytes;
    }

    return ReadHexBytes($"Enter {label} as hex: ");
}

/// <summary>
/// Display serialized key blob hex and inferred block size for the symmetric key.<br/>
/// </summary>
void PrintSymmetricKeyInfo(ZifikaKey key)
{
    var blob = key.ToBytes();
    int keyLen = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(1, 4));
    int blockSize = keyLen / 256;
    Console.WriteLine($" Symmetric key blockSize: {blockSize}");
    WriteLineColor(ConsoleColor.Yellow, $" Symmetric key blob (hex): {HexWithLen(blob)}");
    lastSymKeyHex = Convert.ToHexString(blob);
}

void ShowCurrentSymmetricKey()
{
    if (lastSymKeyHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No symmetric key selected.");
        return;
    }
    int lenBytes = lastSymKeyHex.Length / 2;
    int blockSize = lenBytes / 256;
    string preview = lastSymKeyHex.Length > 80 ? lastSymKeyHex[..80] + "..." : lastSymKeyHex;
    WriteLineColor(ConsoleColor.Yellow, $" Current symmetric key: [len:{lenBytes} bytes, blockSize:{blockSize}] {preview}");
}

void ShowCurrentSymmetricPlain()
{
    if (lastSymPlainHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No symmetric plaintext recorded.");
        return;
    }
    var bytes = Convert.FromHexString(lastSymPlainHex);
    WriteLineColor(ConsoleColor.Yellow, $" Current symmetric plaintext hex: {HexWithLen(bytes)}");
    WriteLineColor(ConsoleColor.White, $" Current symmetric plaintext utf8: {Utf8WithLen(bytes)}");
}

void ShowCurrentSymmetricCipher()
{
    if (lastSymCipherHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No symmetric ciphertext recorded.");
        return;
    }
    var bytes = Convert.FromHexString(lastSymCipherHex);
    WriteLineColor(ConsoleColor.Yellow, $" Current symmetric ciphertext hex: {HexWithLen(bytes)}");
}

void CopyCurrentSymmetricKey() => CopyNow("symmetric key", lastSymKeyHex);
void CopyCurrentSymmetricPlain() => CopyNow("symmetric plaintext", lastSymPlainHex);
void CopyCurrentSymmetricCipher() => CopyNow("symmetric ciphertext", lastSymCipherHex);

/// <summary>
/// Choose or import a symmetric key (new default/custom block size, or hex import).<br/>
/// </summary>
ZifikaKey ResolveSymmetricKey()
{
    while (true)
    {
        Console.WriteLine();
        PrintBreadcrumb(BuildBreadcrumbPath("Key Selection"));
        WriteLineColor(ConsoleColor.Cyan, "Symmetric key options:");
        Console.WriteLine("  A) New key (default blockSize=8)");
        Console.WriteLine("  B) New key (custom blockSize)");
        Console.WriteLine("  C) Import key from hex (REKey.ToBytes)");
        Console.WriteLine($"  ?) {GlossaryLabel}");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A/B/C/?/X or ESC): ", "A", "B", "C", "?", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return null;
        if (string.Equals(choice, "?", StringComparison.OrdinalIgnoreCase)) { WithBreadcrumb("Key Selection", () => RunGlossaryMenu(GlossaryContextSymmetricKey)); continue; }
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
        {
            var key = Zifika.CreateKey();
            PrintSymmetricKeyInfo(key);
            return key;
        }
        if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            var blkStr = ReadRequiredCancelable("Enter block size (rows, 1-255, blank to cancel): ");
            if (blkStr == null) continue;
            if (byte.TryParse(blkStr, out var blk) && blk > 0)
            {
                var key = Zifika.CreateKey(blk);
                PrintSymmetricKeyInfo(key);
                return key;
            }
            WriteLineColor(ConsoleColor.Red, "Invalid block size.");
        }
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = ReadHexBytes("Enter key blob hex: ");
            if (bytes == null) continue;
            try
            {
                var key = Zifika.CreateKeyFromBytes(bytes);
                PrintSymmetricKeyInfo(key);
                return key;
            }
            catch (Exception ex)
            {
                WriteLineColor(ConsoleColor.Red, $"Failed to import key: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }
}

/// <summary>
/// Run a deterministic forced-transcript regression where plaintexts differ only at byte 0 and must not re-synchronize from byte 2 onward.<br/>
/// Uses a deterministic key seed plus explicit startLocation/intCat to force identical transcript inputs across both encryptions.<br/>
/// Also verifies both ciphertexts still roundtrip through UnmapData to preserve symmetric correctness.<br/>
/// </summary>
/// <returns>
/// A tuple containing pass/fail state, roundtrip results, suffix-divergence result, and both ciphertexts for optional diagnostics.<br/>
/// </returns>
(bool Passed, bool RoundtripA, bool RoundtripB, bool SuffixDifferent, byte[] CipherA, byte[] CipherB) RunForcedTranscriptDivergenceRegression()
{
    byte[] seed = new byte[]
    {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x0F
    };
    using var deterministicKey = Zifika.CreateKey(seed, keySize: 8);

    const short startLocation = unchecked((short)0x3A5C);
    byte[] intCat = Encoding.ASCII.GetBytes("forced-transcript-cat");

    byte[] plainA = Encoding.ASCII.GetBytes("zifika-regression-plaintext");
    byte[] plainB = (byte[])plainA.Clone();
    plainB[0] ^= 0x5A;

    byte[] cipherABytes;
    using (var cipherA = deterministicKey.MapData(plainA, startLocation, intCat))
        cipherABytes = cipherA.AsReadOnlySpan.ToArray();

    byte[] cipherBBytes;
    using (var cipherB = deterministicKey.MapData(plainB, startLocation, intCat))
        cipherBBytes = cipherB.AsReadOnlySpan.ToArray();

    bool suffixDifferent;
    if (cipherABytes.Length > 2 && cipherBBytes.Length > 2)
        suffixDifferent = !cipherABytes.AsSpan(2).SequenceEqual(cipherBBytes.AsSpan(2));
    else
        suffixDifferent = !cipherABytes.AsSpan().SequenceEqual(cipherBBytes.AsSpan());

    bool roundtripA;
    using (var recoveredA = deterministicKey.UnmapData(new ZifikaBufferStream(cipherABytes), startLocation, intCat))
        roundtripA = recoveredA != null && plainA.AsSpan().SequenceEqual(recoveredA.AsReadOnlySpan);

    bool roundtripB;
    using (var recoveredB = deterministicKey.UnmapData(new ZifikaBufferStream(cipherBBytes), startLocation, intCat))
        roundtripB = recoveredB != null && plainB.AsSpan().SequenceEqual(recoveredB.AsReadOnlySpan);

    bool passed = roundtripA && roundtripB && suffixDifferent;
    return (passed, roundtripA, roundtripB, suffixDifferent, cipherABytes, cipherBBytes);
}

/// <summary>
/// Run pre-canned symmetric encrypt/decrypt pairs with the current key and print before/after info.<br/>
/// </summary>
void RunSymmetricPreset(ZifikaKey key, bool useIntegrity)
{
    WriteLineColor(ConsoleColor.Cyan, "=== Symmetric pre-canned cases ===");
    foreach (var (label, plain) in BuildPresetPayloads())
    {
        var ct = Zifika.Encrypt(plain, key, useIntegrity);
        var ctBytes = ct.ToArray();
        var dec = Zifika.Decrypt(new ZifikaBufferStream(ctBytes), key, useIntegrity);
        var decBytes = dec?.ToArray() ?? Array.Empty<byte>();
        bool match = dec != null && plain.AsSpan().SequenceEqual(decBytes);
        lastSymCipherHex = Convert.ToHexString(ctBytes);
        lastSymPlainHex = Convert.ToHexString(plain);
        Console.WriteLine($"[{label}] plaintext utf8: {Utf8WithLen(plain)}");
        Console.WriteLine($"[{label}] plaintext hex:  {HexWithLen(plain)}");
        Console.WriteLine($"[{label}] ciphertext:    {HexWithLen(ctBytes)} (overhead:{ctBytes.Length - plain.Length})");
        Console.WriteLine($"[{label}] decrypted:     {Utf8WithLen(decBytes)}");
        WriteLineColor(match ? ConsoleColor.Green : ConsoleColor.Red,
            $"[{label}] Plaintext Decrypt Matches Original: {match}");
        Console.WriteLine();
    }

    var regression = RunForcedTranscriptDivergenceRegression();
    WriteLineColor(ConsoleColor.Cyan, "[Regression] Forced transcript divergence");
    Console.WriteLine($"[Regression] Cipher A: {HexWithLen(regression.CipherA)}");
    Console.WriteLine($"[Regression] Cipher B: {HexWithLen(regression.CipherB)}");
    WriteLineColor(regression.SuffixDifferent ? ConsoleColor.Green : ConsoleColor.Red,
        $"[Regression] Cipher suffixes from byte 2 differ: {regression.SuffixDifferent}");
    WriteLineColor(regression.RoundtripA ? ConsoleColor.Green : ConsoleColor.Red,
        $"[Regression] Roundtrip A passed: {regression.RoundtripA}");
    WriteLineColor(regression.RoundtripB ? ConsoleColor.Green : ConsoleColor.Red,
        $"[Regression] Roundtrip B passed: {regression.RoundtripB}");
    WriteLineColor(regression.Passed ? ConsoleColor.Green : ConsoleColor.Red,
        $"[Regression] Forced transcript non-resync overall: {regression.Passed}");
    Console.WriteLine();
}

/// <summary>
/// Run symmetric attack simulations against deterministic ciphertexts and report whether tampering is blocked or garbles output.<br/>
/// Intended as sample code for reviewers to reproduce common manipulation attempts without editing core library code.<br/>
/// </summary>
/// <param name="requireIntegrity">Integrity requirement used during decrypt attempts.<br/></param>
/// <param name="detail">When true, prints per-mutation ciphertext previews and all fuzz iterations.<br/></param>
void RunSymmetricAttackPreset(bool requireIntegrity, bool detail)
{
    WriteLineColor(ConsoleColor.Cyan, $"=== Symmetric attack simulations (integrity:{(requireIntegrity ? "on" : "off")}, detail:{(detail ? "on" : "off")}) ===");
    byte[] deterministicSeed = new byte[]
    {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21
    };
    using var key = Zifika.CreateKey(deterministicSeed, keySize: 8);

    var payloads = BuildAttackPayloads();
    var vectors = new List<(string Label, byte[] Plain, byte[] Cipher)>(payloads.Count);
    foreach (var (label, plain) in payloads)
    {
        using var ct = Zifika.Encrypt(plain, key, useIntegrity: requireIntegrity);
        vectors.Add((label, plain, ct.ToArray()));
    }

    int totalCases = 0;
    int blockedOrGarbledCases = 0;
    byte[] appendGarbage = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44 };

    for (int i = 0; i < vectors.Count; i++)
    {
        var current = vectors[i];
        var peer = vectors[(i + 1) % vectors.Count];
        lastSymPlainHex = Convert.ToHexString(current.Plain);
        lastSymCipherHex = Convert.ToHexString(current.Cipher);

        void RunCase(string attackName, byte[] tampered)
        {
            totalCases++;
            bool blocked = IsSymmetricBlockedOrGarbled(tampered, current.Plain, key, requireIntegrity, out string outcome);
            if (blocked) blockedOrGarbledCases++;
            PrintAttackLine("sym", current.Label, attackName, blocked, outcome, detail, tampered);
        }

        RunCase("flip-byte-0", MutateFlipByte(current.Cipher, 0));
        RunCase("flip-byte-4", MutateFlipByte(current.Cipher, 4));
        RunCase("flip-byte-middle", MutateFlipByte(current.Cipher, current.Cipher.Length / 2, 0x04));
        RunCase("flip-byte-tail", MutateFlipByte(current.Cipher, current.Cipher.Length - 1, 0x80));
        RunCase("truncate-minus-1", MutateTruncate(current.Cipher, 1));
        RunCase("truncate-minus-8", MutateTruncate(current.Cipher, 8));
        RunCase("append-garbage-8", MutateAppend(current.Cipher, appendGarbage));
        RunCase("splice-half-with-peer", MutateSpliceHalf(current.Cipher, peer.Cipher));

        totalCases++;
        Span<byte> wrongSeed = stackalloc byte[16];
        int wrongSeedBase = StableSeedFromLabel("sym-wrong-key-" + current.Label);
        BinaryPrimitives.WriteInt32LittleEndian(wrongSeed.Slice(0, 4), wrongSeedBase);
        BinaryPrimitives.WriteInt32LittleEndian(wrongSeed.Slice(4, 4), wrongSeedBase ^ 0x13579BDF);
        BinaryPrimitives.WriteInt32LittleEndian(wrongSeed.Slice(8, 4), wrongSeedBase ^ unchecked((int)0x89ABCDEF));
        BinaryPrimitives.WriteInt32LittleEndian(wrongSeed.Slice(12, 4), wrongSeedBase ^ 0x2468ACE0);
        using (var wrongKey = Zifika.CreateKey(wrongSeed, keySize: 8))
        {
            bool blocked = IsSymmetricBlockedOrGarbled(current.Cipher, current.Plain, wrongKey, requireIntegrity, out string outcome);
            if (blocked) blockedOrGarbledCases++;
            PrintAttackLine("sym", current.Label, "wrong-key", blocked, outcome, detail, current.Cipher);
        }

        const int fuzzCount = 64;
        int fuzzBlocked = 0;
        var rng = new Random(StableSeedFromLabel("sym-fuzz-" + current.Label) ^ current.Cipher.Length);
        for (int f = 0; f < fuzzCount; f++)
        {
            totalCases++;
            int idx = current.Cipher.Length == 0 ? 0 : rng.Next(current.Cipher.Length);
            int bit = rng.Next(8);
            byte mask = (byte)(1 << bit);
            var tampered = MutateFlipByte(current.Cipher, idx, mask);
            bool blocked = IsSymmetricBlockedOrGarbled(tampered, current.Plain, key, requireIntegrity, out string outcome);
            if (blocked)
            {
                blockedOrGarbledCases++;
                fuzzBlocked++;
            }
            if (detail || !blocked)
                PrintAttackLine("sym", current.Label, $"fuzz-{f + 1:D2}@{idx}/0x{mask:X2}", blocked, outcome, detail, tampered);
        }

        if (!detail)
            WriteLineColor(ConsoleColor.Red, $"[sym-attack][{current.Label}] fuzz-summary: blocked-or-garbled={fuzzBlocked}/{fuzzCount}");
    }

    WriteLineColor(ConsoleColor.Red, $"[sym-attack] overall blocked-or-garbled={blockedOrGarbledCases}/{totalCases}");
    Console.WriteLine();
}

/// <summary>
/// Interactive symmetric encrypt with the current key; prints plaintext/ciphertext and overhead.<br/>
/// </summary>
void SymmetricEncryptInteractive(ZifikaKey key, bool useIntegrity)
{
    var plain = PromptPayloadBytes("plaintext");
    if (plain == null) return;
    // new plaintext invalidates prior ciphertext
    lastSymCipherHex = null;
    var ct = Zifika.Encrypt(plain, key, useIntegrity);
    var ctBytes = ct.ToArray();
    lastSymCipherHex = Convert.ToHexString(ctBytes);
    lastSymPlainHex = Convert.ToHexString(plain);
    var dec = Zifika.Decrypt(new ZifikaBufferStream(ctBytes), key, useIntegrity);
    var decBytes = dec?.ToArray() ?? Array.Empty<byte>();
    bool match = dec != null && plain.AsSpan().SequenceEqual(decBytes);
    WriteLineColor(ConsoleColor.Cyan, "=== Symmetric encrypt ===");
    Console.WriteLine($" plaintext utf8: {Utf8WithLen(plain)}");
    Console.WriteLine($" plaintext hex:  {HexWithLen(plain)}");
    Console.WriteLine($" ciphertext:     {HexWithLen(ctBytes)} (overhead:{ctBytes.Length - plain.Length})");
    WriteLineColor(match ? ConsoleColor.Green : ConsoleColor.Red, $" Plaintext Decrypt Matches Original: {match}");
}

/// <summary>
/// Interactive symmetric decrypt with the current key; prints ciphertext and recovered plaintext.<br/>
/// </summary>
void SymmetricDecryptInteractive(ZifikaKey key, bool requireIntegrity)
{
    var ctBytes = PromptPayloadBytes("ciphertext (hex preferred)");
    if (ctBytes == null) return;
    WriteLineColor(ConsoleColor.Cyan, "=== Symmetric decrypt ===");
    Console.WriteLine($" ciphertext: {HexWithLen(ctBytes)}");
    lastSymCipherHex = Convert.ToHexString(ctBytes);
    ZifikaBufferStream dec = null;
    try
    {
        dec = Zifika.Decrypt(new ZifikaBufferStream(ctBytes), key, requireIntegrity);
    }
    catch (Exception ex)
    {
        WriteLineColor(ConsoleColor.Red, $" decrypt exception: {ex.GetType().Name}: {ex.Message}");
    }

    if (dec == null)
    {
        WriteLineColor(ConsoleColor.Red, " decrypt failed (null result)");
        return;
    }

    var plain = dec.ToArray();
    lastSymPlainHex = Convert.ToHexString(plain);
    Console.WriteLine($" plaintext utf8: {Utf8WithLen(plain)}");
    Console.WriteLine($" plaintext hex:  {HexWithLen(plain)}");
    WriteLineColor(ConsoleColor.DarkGray, " Plaintext Decrypt Matches Original: n/a");
}

/// <summary>
/// Symmetric menu: choose key, run pre-canned cases, encrypt, decrypt.<br/>
/// </summary>
bool HasSymKey() => lastSymKeyHex != null;
bool HasSymPlain() => lastSymPlainHex != null;
bool HasSymCipher() => lastSymCipherHex != null;

bool HasMinting() => lastMintHex != null;
bool HasVerifier() => lastVerifierHex != null;
bool HasMintPlain() => lastMintPlainHex != null;
bool HasMintCipher() => lastMintCipherHex != null;

void RunSymmetricMenu()
{
    breadcrumb = new List<string> { "Main", "Symmetric" };
    bool useIntegritySym = true;
    var key = ResolveSymmetricKey();
    if (key == null) return;
    while (true)
    {
        Console.WriteLine();
        PrintBreadcrumb();
        WriteLineColor(ConsoleColor.Cyan, "Symmetric menu:");
        Console.WriteLine($"  A) Pre-canned demo (integrity:{(useIntegritySym ? "on" : "off")})");
        Console.WriteLine("  B) Encrypt plaintext");
        Console.WriteLine("  C) Decrypt ciphertext");
        Console.WriteLine("  D) Toggle integrity seal on/off");
        Console.WriteLine($"  E) Show current key {(HasSymKey() ? "[set]" : "[none]")}");
        Console.WriteLine($"  F) Show current plaintext {(HasSymPlain() ? "[set]" : "[none]")}");
        Console.WriteLine($"  G) Show current ciphertext {(HasSymCipher() ? "[set]" : "[none]")}");
        Console.WriteLine($"  H) Copy current key {(HasSymKey() ? "[set]" : "[none]")}");
        Console.WriteLine($"  I) Copy current plaintext {(HasSymPlain() ? "[set]" : "[none]")}");
        Console.WriteLine($"  J) Copy current ciphertext {(HasSymCipher() ? "[set]" : "[none]")}");
        Console.WriteLine("  K) Change key");
        Console.WriteLine($"  ?) {GlossaryLabel}");
        Console.WriteLine("  M) Integrity mode");
        Console.WriteLine("  N) Key sizing & variability");
        Console.WriteLine("  O) Plaintext size & performance");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A-O/?/X or ESC): ", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "M", "N", "O", "?", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) RunSymmetricPreset(key, useIntegritySym);
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase)) SymmetricEncryptInteractive(key, useIntegritySym);
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase)) SymmetricDecryptInteractive(key, useIntegritySym);
        else if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase)) useIntegritySym = !useIntegritySym;
        else if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase)) ShowCurrentSymmetricKey();
        else if (string.Equals(choice, "F", StringComparison.OrdinalIgnoreCase)) ShowCurrentSymmetricPlain();
        else if (string.Equals(choice, "G", StringComparison.OrdinalIgnoreCase)) ShowCurrentSymmetricCipher();
        else if (string.Equals(choice, "H", StringComparison.OrdinalIgnoreCase)) CopyCurrentSymmetricKey();
        else if (string.Equals(choice, "I", StringComparison.OrdinalIgnoreCase)) CopyCurrentSymmetricPlain();
        else if (string.Equals(choice, "J", StringComparison.OrdinalIgnoreCase)) CopyCurrentSymmetricCipher();
        else if (string.Equals(choice, "K", StringComparison.OrdinalIgnoreCase))
        {
            var newKey = ResolveSymmetricKey();
            if (newKey != null) key = newKey;
        }
        else if (string.Equals(choice, "?", StringComparison.OrdinalIgnoreCase)) RunGlossaryMenu(GlossaryContextSymmetric);
        else if (string.Equals(choice, "M", StringComparison.OrdinalIgnoreCase)) RunGlossaryMenuAtKey("Integrity");
        else if (string.Equals(choice, "N", StringComparison.OrdinalIgnoreCase)) RunGlossaryMenuAtKey("Keys");
        else if (string.Equals(choice, "O", StringComparison.OrdinalIgnoreCase)) RunGlossaryMenuAtKey("Input");
    }
}

/// <summary>
/// Print minting/verifier blobs for Mint/Verify mode with len-tagged hex.<br/>
/// </summary>
void PrintMintingInfo(ZifikaMintingKey minting, ZifikaVerifierKey vKey)
{
    var mintBlob = minting.ToBytes();
    var verBlob = vKey.ToBytes();
    Console.WriteLine($" Minting key blob (hex): {HexWithLen(mintBlob)}");
    Console.WriteLine($" Verifier key blob (hex): {HexWithLen(verBlob)}");
    lastMintHex = Convert.ToHexString(mintBlob);
    lastVerifierHex = Convert.ToHexString(verBlob);
}

void ShowCurrentMintVerifyKeys()
{
    if (lastMintHex == null && lastVerifierHex == null)
    {
        Console.WriteLine(" No mint/verify keys selected.");
        return;
    }
    if (lastMintHex != null)
    {
        int lenBytes = lastMintHex.Length / 2;
        string preview = lastMintHex.Length > 80 ? lastMintHex[..80] + "..." : lastMintHex;
        WriteLineColor(ConsoleColor.Yellow, $" Minting key: [len:{lenBytes}] {preview}");
    }
    if (lastVerifierHex != null)
    {
        int lenBytes = lastVerifierHex.Length / 2;
        string preview = lastVerifierHex.Length > 80 ? lastVerifierHex[..80] + "..." : lastVerifierHex;
        WriteLineColor(ConsoleColor.Yellow, $" Verifier key: [len:{lenBytes}] {preview}");
    }
}

void ShowCurrentMintPlain()
{
    if (lastMintPlainHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No mint plaintext recorded.");
        return;
    }
    var bytes = Convert.FromHexString(lastMintPlainHex);
    WriteLineColor(ConsoleColor.Yellow, $" Current mint plaintext hex: {HexWithLen(bytes)}");
    WriteLineColor(ConsoleColor.White, $" Current mint plaintext utf8: {Utf8WithLen(bytes)}");
}

void ShowCurrentMintCipher()
{
    if (lastMintCipherHex == null)
    {
        WriteLineColor(ConsoleColor.DarkGray, " No mint ciphertext recorded.");
        return;
    }
    var bytes = Convert.FromHexString(lastMintCipherHex);
    WriteLineColor(ConsoleColor.Yellow, $" Current mint ciphertext hex: {HexWithLen(bytes)}");
}

void CopyCurrentMintingKey() => CopyNow("minting key", lastMintHex);
void CopyCurrentVerifierKey() => CopyNow("verifier key", lastVerifierHex);
void CopyCurrentMintPlain() => CopyNow("mint plaintext", lastMintPlainHex);
void CopyCurrentMintCipher() => CopyNow("mint ciphertext", lastMintCipherHex);

/// <summary>
/// Prompt for a minting/verifier selection: new pair, import minting hex (derives verifier), or import verifier hex.<br/>
/// </summary>
void SelectMintVerifyKeys(ref ZifikaMintingKey minting, ref ZifikaVerifierKey vKey)
{
    while (true)
    {
        Console.WriteLine();
        PrintBreadcrumb(BuildBreadcrumbPath("Key Options"));
        WriteLineColor(ConsoleColor.Cyan, "Mint/Verify key options:");
        Console.WriteLine("  A) New minting/verifier pair");
        Console.WriteLine("  B) Import minting key from hex (derives verifier)");
        Console.WriteLine("  C) Import verifier key from hex");
        Console.WriteLine($"  ?) {GlossaryLabel}");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A/B/C/?/X or ESC): ", "A", "B", "C", "?", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "?", StringComparison.OrdinalIgnoreCase)) { WithBreadcrumb("Key Options", () => RunGlossaryMenu(GlossaryContextMintVerifyKey)); continue; }
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
        {
            var pair = Zifika.CreateMintingKeyPair();
            minting = pair.minting;
            vKey = pair.verifier;
            PrintMintingInfo(minting, vKey);
            lastMintHex = Convert.ToHexString(minting.ToBytes());
            lastVerifierHex = Convert.ToHexString(vKey.ToBytes());
            return;
        }
        if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            var blob = ReadHexBytes("Enter minting key blob (hex): ");
            if (blob == null) continue;
            try
            {
                minting = Zifika.CreateMintingKey(blob);
                vKey = minting.CreateVerifierKey();
                PrintMintingInfo(minting, vKey);
                lastMintHex = Convert.ToHexString(minting.ToBytes());
                lastVerifierHex = Convert.ToHexString(vKey.ToBytes());
                return;
            }
            catch (Exception ex)
            {
                WriteLineColor(ConsoleColor.Red, $"Failed to import minting key: {ex.GetType().Name}: {ex.Message}");
            }
        }
        if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase))
        {
            var blob = ReadHexBytes("Enter verifier key blob (hex): ");
            if (blob == null) continue;
            try
            {
                vKey = Zifika.CreateVerifierKey(blob);
                WriteLineColor(ConsoleColor.Yellow, $" Verifier key blob (hex): {HexWithLen(blob)}");
                if (minting != null)
                    PrintMintingInfo(minting, vKey);
                lastVerifierHex = Convert.ToHexString(vKey.ToBytes());
                return;
            }
            catch (Exception ex)
            {
                WriteLineColor(ConsoleColor.Red, $"Failed to import verifier key: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }
}

/// <summary>
/// Run pre-canned Mint/Verify mint/verify pairs with before/after metrics.<br/>
/// </summary>
void RunMintVerifyPreset(ZifikaMintingKey minting, ZifikaVerifierKey vKey, bool useIntegrity)
{
    WriteLineColor(ConsoleColor.Cyan, "=== Mint/Verify pre-canned cases ===");
    foreach (var (label, plain) in BuildPresetPayloads())
    {
        var ct = Zifika.Mint(plain, minting, useIntegrity: useIntegrity);
        var ctBytes = ct.ToArray();
        ZifikaBufferStream dec = null;
        try
        {
            dec = Zifika.VerifyAndDecrypt(new ZifikaBufferStream(ctBytes), vKey, requireIntegrity: useIntegrity);
        }
        catch (InvalidDataException ex)
        {
            Console.WriteLine($"[{label}] decrypt error: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{label}] decrypt exception: {ex.GetType().Name}: {ex.Message}");
        }
        var decBytes = dec?.ToArray() ?? Array.Empty<byte>();
        bool match = dec != null && plain.AsSpan().SequenceEqual(decBytes);
        lastMintCipherHex = Convert.ToHexString(ctBytes);
        lastMintPlainHex = Convert.ToHexString(plain);

        Console.WriteLine($"[{label}] plaintext utf8: {Utf8WithLen(plain)}");
        Console.WriteLine($"[{label}] plaintext hex:  {HexWithLen(plain)}");
        Console.WriteLine($"[{label}] ciphertext:     {HexWithLen(ctBytes)} (overhead:{ctBytes.Length - plain.Length})");
        Console.WriteLine($"[{label}] decrypted:      {Utf8WithLen(decBytes)}");
        WriteLineColor(match ? ConsoleColor.Green : ConsoleColor.Red,
            $"[{label}] Plaintext Decrypt Matches Original: {match}");
        Console.WriteLine();
    }
}

/// <summary>
/// Run mint/verify attack simulations and report whether tampering is blocked or garbles output.<br/>
/// Uses one minting/verifier pair plus a second verifier for wrong-key checks.<br/>
/// </summary>
/// <param name="requireIntegrity">Integrity requirement used during verify/decrypt attempts.<br/></param>
/// <param name="detail">When true, prints per-mutation ciphertext previews and all fuzz iterations.<br/></param>
void RunMintVerifyAttackPreset(bool requireIntegrity, bool detail)
{
    WriteLineColor(ConsoleColor.Cyan, $"=== Mint/Verify attack simulations (integrity:{(requireIntegrity ? "on" : "off")}, detail:{(detail ? "on" : "off")}) ===");

    var primaryPair = Zifika.CreateMintingKeyPair();
    var minting = primaryPair.minting;
    var verifier = primaryPair.verifier;
    var wrongPair = Zifika.CreateMintingKeyPair();
    var wrongVerifier = wrongPair.verifier;

    var payloads = BuildAttackPayloads();
    var vectors = new List<(string Label, byte[] Plain, byte[] Cipher)>(payloads.Count);
    foreach (var (label, plain) in payloads)
    {
        using var ct = Zifika.Mint(plain, minting, useIntegrity: requireIntegrity);
        vectors.Add((label, plain, ct.ToArray()));
    }

    int totalCases = 0;
    int blockedOrGarbledCases = 0;
    byte[] appendGarbage = new byte[] { 0x44, 0x33, 0x22, 0x11, 0xA5, 0x5A, 0xC3, 0x3C };

    for (int i = 0; i < vectors.Count; i++)
    {
        var current = vectors[i];
        var peer = vectors[(i + 1) % vectors.Count];
        lastMintPlainHex = Convert.ToHexString(current.Plain);
        lastMintCipherHex = Convert.ToHexString(current.Cipher);

        void RunCase(string attackName, byte[] tampered)
        {
            totalCases++;
            bool blocked = IsMintVerifyBlockedOrGarbled(tampered, current.Plain, verifier, requireIntegrity, out string outcome);
            if (blocked) blockedOrGarbledCases++;
            PrintAttackLine("m/v", current.Label, attackName, blocked, outcome, detail, tampered);
        }

        RunCase("flip-vkeylock-byte-0", MutateFlipByte(current.Cipher, 0));
        RunCase("flip-control-byte-20", MutateFlipByte(current.Cipher, 20));
        RunCase("flip-byte-middle", MutateFlipByte(current.Cipher, current.Cipher.Length / 2, 0x08));
        RunCase("flip-byte-tail", MutateFlipByte(current.Cipher, current.Cipher.Length - 1, 0x40));
        RunCase("truncate-minus-1", MutateTruncate(current.Cipher, 1));
        RunCase("truncate-minus-16", MutateTruncate(current.Cipher, 16));
        RunCase("append-garbage-8", MutateAppend(current.Cipher, appendGarbage));
        RunCase("splice-half-with-peer", MutateSpliceHalf(current.Cipher, peer.Cipher));

        totalCases++;
        bool wrongVerifierBlocked = IsMintVerifyBlockedOrGarbled(current.Cipher, current.Plain, wrongVerifier, requireIntegrity, out string wrongVerifierOutcome);
        if (wrongVerifierBlocked) blockedOrGarbledCases++;
        PrintAttackLine("m/v", current.Label, "wrong-verifier-key", wrongVerifierBlocked, wrongVerifierOutcome, detail, current.Cipher);

        const int fuzzCount = 64;
        int fuzzBlocked = 0;
        var rng = new Random(StableSeedFromLabel("mv-fuzz-" + current.Label) ^ current.Cipher.Length);
        for (int f = 0; f < fuzzCount; f++)
        {
            totalCases++;
            int idx = current.Cipher.Length == 0 ? 0 : rng.Next(current.Cipher.Length);
            int bit = rng.Next(8);
            byte mask = (byte)(1 << bit);
            var tampered = MutateFlipByte(current.Cipher, idx, mask);
            bool blocked = IsMintVerifyBlockedOrGarbled(tampered, current.Plain, verifier, requireIntegrity, out string outcome);
            if (blocked)
            {
                blockedOrGarbledCases++;
                fuzzBlocked++;
            }
            if (detail || !blocked)
                PrintAttackLine("m/v", current.Label, $"fuzz-{f + 1:D2}@{idx}/0x{mask:X2}", blocked, outcome, detail, tampered);
        }

        if (!detail)
            WriteLineColor(ConsoleColor.Red, $"[m/v-attack][{current.Label}] fuzz-summary: blocked-or-garbled={fuzzBlocked}/{fuzzCount}");
    }

    WriteLineColor(ConsoleColor.Red, $"[m/v-attack] overall blocked-or-garbled={blockedOrGarbledCases}/{totalCases}");
    Console.WriteLine();
}

/// <summary>
/// Interactive Mint/Verify mint (encrypt) with the current minting key; prints blobs and overhead.<br/>
/// </summary>
void MintInteractive(ZifikaMintingKey minting, ZifikaVerifierKey vKey, bool useIntegrity)
{
    var plain = PromptPayloadBytes("plaintext");
    if (plain == null) return;
    // new plaintext invalidates prior ciphertext snapshot
    lastMintCipherHex = null;
    var ct = Zifika.Mint(plain, minting, useIntegrity: useIntegrity);
    var ctBytes = ct.ToArray();
    lastMintCipherHex = Convert.ToHexString(ctBytes);
    lastMintPlainHex = Convert.ToHexString(plain);
    ZifikaBufferStream dec = null;
    try
    {
        dec = Zifika.VerifyAndDecrypt(new ZifikaBufferStream(ctBytes), vKey, requireIntegrity: useIntegrity);
    }
    catch (InvalidDataException ex)
    {
        Console.WriteLine($" verify error: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($" verify exception: {ex.GetType().Name}: {ex.Message}");
    }
    var decBytes = dec?.ToArray() ?? Array.Empty<byte>();
    bool match = dec != null && plain.AsSpan().SequenceEqual(decBytes);
    WriteLineColor(ConsoleColor.Cyan, "=== Mint (encrypt) ===");
    PrintMintingInfo(minting, vKey);
    Console.WriteLine($" plaintext utf8: {Utf8WithLen(plain)}");
    Console.WriteLine($" plaintext hex:  {HexWithLen(plain)}");
    Console.WriteLine($" ciphertext:     {HexWithLen(ctBytes)} (overhead:{ctBytes.Length - plain.Length})");
    WriteLineColor(match ? ConsoleColor.Green : ConsoleColor.Red, $" Plaintext Decrypt Matches Original: {match}");
}

/// <summary>
/// Interactive Mint/Verify verify/decrypt with the current verifier key.<br/>
/// </summary>
void VerifyInteractive(ZifikaVerifierKey vKey, bool requireIntegrity)
{
    var ctBytes = PromptPayloadBytes("ciphertext (hex preferred)");
    if (ctBytes == null) return;
    WriteLineColor(ConsoleColor.Cyan, "=== Verify ===");
    Console.WriteLine($" ciphertext: {HexWithLen(ctBytes)}");
    lastMintCipherHex = Convert.ToHexString(ctBytes);
    ZifikaBufferStream dec = null;
    try
    {
        dec = Zifika.VerifyAndDecrypt(new ZifikaBufferStream(ctBytes), vKey, requireIntegrity: requireIntegrity);
    }
    catch (InvalidDataException ex)
    {
        Console.WriteLine($" verify error: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($" verify exception: {ex.GetType().Name}: {ex.Message}");
    }

    if (dec == null)
    {
        WriteLineColor(ConsoleColor.Red, " verify failed (null result)");
        return;
    }

    var plain = dec.ToArray();
    lastMintPlainHex = Convert.ToHexString(plain);
    Console.WriteLine($" plaintext utf8: {Utf8WithLen(plain)}");
    Console.WriteLine($" plaintext hex:  {HexWithLen(plain)}");
    WriteLineColor(ConsoleColor.DarkGray, " Plaintext Decrypt Matches Original: n/a");
}

/// <summary>
/// Mint/Verify menu: select keys, pre-canned demo, mint, verify.<br/>
/// </summary>
void RunMintVerifyMenu()
{
    breadcrumb = new List<string> { "Main", "Mint/Verify" };
    if (showMintVerifyIntro)
        ShowMintVerifyIntro(ref showMintVerifyIntro);
    ZifikaMintingKey minting = null;
    ZifikaVerifierKey verifier = null;
    bool useIntegrity = true;
    SelectMintVerifyKeys(ref minting, ref verifier);

    while (true)
    {
        Console.WriteLine();
        PrintBreadcrumb();
        WriteLineColor(ConsoleColor.Cyan, "Mint/Verify menu (mint/verify):");
        Console.WriteLine($"  A) Pre-canned demo (integrity:{(useIntegrity ? "on" : "off")})");
        Console.WriteLine("  B) Mint (encrypt) plaintext");
        Console.WriteLine("  C) Verify (decrypt) ciphertext");
        Console.WriteLine("  D) Toggle integrity seal on/off");
        Console.WriteLine($"  E) Show current keys {(HasMinting() || HasVerifier() ? "[set]" : "[none]")}");
        Console.WriteLine($"  F) Show current plaintext {(HasMintPlain() ? "[set]" : "[none]")}");
        Console.WriteLine($"  G) Show current ciphertext {(HasMintCipher() ? "[set]" : "[none]")}");
        Console.WriteLine($"  H) Copy minting key {(HasMinting() ? "[set]" : "[none]")}");
        Console.WriteLine($"  I) Copy verifier key {(HasVerifier() ? "[set]" : "[none]")}");
        Console.WriteLine($"  J) Copy current plaintext {(HasMintPlain() ? "[set]" : "[none]")}");
        Console.WriteLine($"  K) Copy current ciphertext {(HasMintCipher() ? "[set]" : "[none]")}");
        Console.WriteLine("  L) Change keys");
        Console.WriteLine($"  ?) {GlossaryLabel}");
        Console.WriteLine("  M) Why \"mint/verify\"?");
        Console.WriteLine("  N) Use cases");
        Console.WriteLine("  O) Failure semantics");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A-O/?/X or ESC): ", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "?", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase))
        {
            useIntegrity = !useIntegrity;
            continue;
        }
        if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase)) { ShowCurrentMintVerifyKeys(); continue; }
        if (string.Equals(choice, "F", StringComparison.OrdinalIgnoreCase)) { ShowCurrentMintPlain(); continue; }
        if (string.Equals(choice, "G", StringComparison.OrdinalIgnoreCase)) { ShowCurrentMintCipher(); continue; }
        if (string.Equals(choice, "H", StringComparison.OrdinalIgnoreCase)) { CopyCurrentMintingKey(); continue; }
        if (string.Equals(choice, "I", StringComparison.OrdinalIgnoreCase)) { CopyCurrentVerifierKey(); continue; }
        if (string.Equals(choice, "J", StringComparison.OrdinalIgnoreCase)) { CopyCurrentMintPlain(); continue; }
        if (string.Equals(choice, "K", StringComparison.OrdinalIgnoreCase)) { CopyCurrentMintCipher(); continue; }
        if (string.Equals(choice, "L", StringComparison.OrdinalIgnoreCase)) { SelectMintVerifyKeys(ref minting, ref verifier); continue; }
        if (string.Equals(choice, "?", StringComparison.OrdinalIgnoreCase)) { RunGlossaryMenu(GlossaryContextMintVerify); continue; }
        if (string.Equals(choice, "M", StringComparison.OrdinalIgnoreCase)) { RunGlossaryMenuAtKey("MintVerifyMode"); continue; }
        if (string.Equals(choice, "N", StringComparison.OrdinalIgnoreCase)) { RunGlossaryMenuAtKey("IntendedProblemSpace"); continue; }
        if (string.Equals(choice, "O", StringComparison.OrdinalIgnoreCase)) { RunGlossaryMenuAtKey("FailClosedBehavior"); continue; }

        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
        {
            if (minting == null || verifier == null)
            {
                WriteLineColor(ConsoleColor.Red, "Pre-canned demo needs both minting and verifier keys (set via key options L).");
                continue;
            }
            RunMintVerifyPreset(minting, verifier, useIntegrity);
        }
        else if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            if (minting == null)
            {
                WriteLineColor(ConsoleColor.Red, "Minting requires a minting key (set via key options L).");
                continue;
            }
            verifier ??= minting.CreateVerifierKey();
            MintInteractive(minting, verifier, useIntegrity);
        }
        else if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase))
        {
            if (verifier == null)
            {
                WriteLineColor(ConsoleColor.Red, "Verification requires a verifier key (set via key options L).");
                continue;
            }
            VerifyInteractive(verifier, useIntegrity);
        }
    }
}

/// <summary>
/// Dedicated attack simulation menu for critics/reviewers to exercise tamper scenarios in both modes.<br/>
/// Keeps attack demos separate from normal happy-path demos and exposes a detail toggle for verbosity control.<br/>
/// </summary>
void RunAttackSimulationMenu()
{
    breadcrumb = new List<string> { "Main", "Attack Simulations" };
    bool symmetricRequireIntegrity = true;
    bool mintVerifyRequireIntegrity = true;

    while (true)
    {
        Console.WriteLine();
        PrintBreadcrumb();
        WriteLineColor(ConsoleColor.Cyan, "Attack simulations menu:");
        Console.WriteLine($"  A) Run symmetric attack simulations (integrity:{(symmetricRequireIntegrity ? "on" : "off")})");
        Console.WriteLine($"  B) Run mint/verify attack simulations (integrity:{(mintVerifyRequireIntegrity ? "on" : "off")})");
        Console.WriteLine("  C) Toggle symmetric integrity requirement");
        Console.WriteLine("  D) Toggle mint/verify integrity requirement");
        Console.WriteLine($"  E) Toggle detail output (currently:{(attackSimulationDetail ? "on" : "off")})");
        Console.WriteLine("  X) Back (ESC)");
        var choice = ReadChoiceKey("Select (A/B/C/D/E/X or ESC): ", "A", "B", "C", "D", "E", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "C", StringComparison.OrdinalIgnoreCase))
        {
            symmetricRequireIntegrity = !symmetricRequireIntegrity;
            continue;
        }
        if (string.Equals(choice, "D", StringComparison.OrdinalIgnoreCase))
        {
            mintVerifyRequireIntegrity = !mintVerifyRequireIntegrity;
            continue;
        }
        if (string.Equals(choice, "E", StringComparison.OrdinalIgnoreCase))
        {
            attackSimulationDetail = !attackSimulationDetail;
            continue;
        }
        if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase))
        {
            RunSymmetricAttackPreset(symmetricRequireIntegrity, attackSimulationDetail);
            continue;
        }
        if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            RunMintVerifyAttackPreset(mintVerifyRequireIntegrity, attackSimulationDetail);
            continue;
        }
    }
}

/// <summary>
/// Entry menu for the Zifika primer harness; choose symmetric or Mint/Verify flows.<br/>
/// </summary>
void RunZifikaPrimer()
{
    PrintPrimerIntro();
    while (true)
    {
        Console.WriteLine();
        breadcrumb = new List<string> { "Main" };
        PrintBreadcrumb();
        WriteLineColor(ConsoleColor.Cyan, "Main menu:");
        Console.WriteLine("  S) Symmetric (encrypt/decrypt)");
        Console.WriteLine("  A) Mint/Verify");
        Console.WriteLine("  T) Attack simulations");
        Console.WriteLine("  Y) Analysis");
        Console.WriteLine($"  ?) {GlossaryLabel}");
        Console.WriteLine("  X) Exit");
        var choice = ReadChoiceKey("Select (S/A/T/Y/?/X or ESC): ", "S", "A", "T", "Y", "?", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "S", StringComparison.OrdinalIgnoreCase)) RunSymmetricMenu();
        else if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) RunMintVerifyMenu();
        else if (string.Equals(choice, "T", StringComparison.OrdinalIgnoreCase)) RunAttackSimulationMenu();
        else if (string.Equals(choice, "Y", StringComparison.OrdinalIgnoreCase)) RunAnalysisMenu();
        else if (string.Equals(choice, "?", StringComparison.OrdinalIgnoreCase)) RunGlossaryMenu(GlossaryContextMain);
    }
}

RunZifikaPrimer();

class GlossaryNode
{
    public string TitleRaw { get; set; }
    public string TitleKey { get; set; }
    public int Level { get; set; }
    public GlossaryNode Parent { get; set; }
    public List<GlossaryNode> Children { get; } = new();
    public List<string> TextLines { get; } = new();
}

class AnalysisModeResult
{
    public string Mode { get; set; }
    public int SampleCount { get; set; }
    public long TotalBytes { get; set; }
    public int RoundtripPassed { get; set; }
    public int RoundtripTotal { get; set; }
    public int TamperBlockedPassed { get; set; }
    public int TamperBlockedTotal { get; set; }
    public int WrongKeyBlockedPassed { get; set; }
    public int WrongKeyBlockedTotal { get; set; }
    public int HardChecksPassed { get; set; }
    public int HardChecksTotal { get; set; }
    public string HardChecksInheritedFrom { get; set; }
    public double EntropyGlobal { get; set; }
    public double ChiSquareGlobal { get; set; }
    public double SerialCorrelationGlobal { get; set; }
    public double BitBalanceGlobal { get; set; }
    public double WireLengthMean { get; set; }
    public double WireLengthStdDev { get; set; }
    public double AvalancheMean { get; set; }
    public double AvalancheStdDev { get; set; }
    public double AvalancheMin { get; set; }
    public double AvalancheMax { get; set; }
    public double AvalancheP05 { get; set; }
    public double AvalancheP50 { get; set; }
    public double AvalancheP95 { get; set; }
    public double DistinguisherAccuracy { get; set; }
    public double TimingTStatistic { get; set; }
    public List<string> StatisticalFlags { get; set; } = new();
}
