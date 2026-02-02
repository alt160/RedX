using RedxLib;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using TextCopy;
// use RedxLib.RedX directly

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
/// The token [[RedX]] is rendered as plain text without colorization.<br/>
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
        if (string.Equals(term, "RedX", StringComparison.OrdinalIgnoreCase))
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

const string GlossaryLabel = "Learn more / Glossary of terms";
const string GlossaryContextMain = "main";
const string GlossaryContextSymmetric = "symmetric";
const string GlossaryContextMintVerify = "mint-verify";
const string GlossaryContextSymmetricKey = "symmetric-key";
const string GlossaryContextMintVerifyKey = "mint-verify-key";

const string GlossaryPrimerSource = @"[[RedX]] Primer

  [[Overview]]
    [[RedX]] is a symmetric cipher construction based
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
      advancing through the [[RedXKey]] grid using
      jump values, landing positions, and offset
      emission.

    [[JumpStream]]
      The [[JumpStream]] is a deterministic sequence
      of jump values derived from [[RedXKey]] and
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
      [[Input]] to [[RedX]] is an ordered sequence of
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

    [[RedXKey]]

      [[WhatItIs]]

        [[SerializedForm]]
          A [[RedXKey]] is represented as a two-
          dimensional grid of bytes. Each row is
          exactly 256 bytes wide and is a permutation
          of values 0–255.

        [[ExecutionForm]]
          In execution form, a [[RedXKey]] exists as
          traversal-defining state. It deterministically
          defines jump generation, landing behavior,
          and offset emission.

      [[WhatItIsNot]]

        [[SerializedForm]]
          A [[RedXKey]] is not a number, scalar, or
          algebraic structure. It does not encode
          block structure or plaintext-dependent
          state.

        [[ExecutionForm]]
          A [[RedXKey]] is not a reversible transform,
          block cipher state, or stream cipher seed.

    [[MintingKey]]

      [[WhatItIs]]

        [[SerializedForm]]
          A [[MintingKey]] is a composite key artifact
          containing complete [[RedXKey]] base data
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
          artifact containing [[RedXKey]] base data
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
      This document defines [[RedX]] mechanics,
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
    ["KeyBaseData"] = "RedXKey"
};

string[] infoCorePathWalking = new[]
{
    "RedX uses an internal [[Jump stream]] to drive a walk over a keyed 2D permutation grid.",
    "Each landing emits a [[Key-row offset stream]] value in the same key row.",
    "Ciphertext is the [[Key-row offset stream]], not the [[Jump stream]].",
    "Decryption regenerates the [[Jump stream]] and replays the walk to recover bytes.",
    "This [[path-walking]] design is the root of symmetric and [[Mint/Verify mode]] behavior."
};

string[] infoPrimerIntro = new[]
{
    "RedX is an experimental [[path-walking]] cipher intended for analysis and review only.",
    "It uses an internal [[Jump stream]] and outputs a [[Key-row offset stream]] as ciphertext.",
    "It is not production-ready and must not be used in security-critical systems.",
    "Ciphertext is the output of a keyed traversal across a 2D permutation grid; decryption replays that walk to recover plaintext.",
    "This primer focuses on usage and capability boundaries; construction details are in the source."
};

string[] infoMintVerifyIntro = new[]
{
    "[[Mint/Verify mode]] in RedX refers to separated capabilities: minting vs verifying.",
    "The roles are intentionally inverted: the verifier key can decrypt and verify that the ciphertext was minted by its paired minting key.",
    "If verification fails, no output is produced.",
    "Verification uses a standard asymmetric signature primitive, applied to the traversal transcript in a RedX-specific way.",
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
    "This is analogous to AEAD, but with RedX mapping semantics."
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
    WriteLineColor(ConsoleColor.Cyan, "RedX primer");
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
    if (topNodes.Count == 1 && string.Equals(topNodes[0].TitleKey, "RedX Primer", StringComparison.OrdinalIgnoreCase))
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
/// Normalize a glossary token for lookup, applying redirects and ignoring [[RedX]].<br/>
/// Returns null when the token should be ignored.<br/>
/// </summary>
string NormalizeGlossaryToken(string token)
{
    if (string.IsNullOrWhiteSpace(token)) return null;
    if (string.Equals(token, "RedX", StringComparison.OrdinalIgnoreCase)) return null;
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
        ("len-1024-mixed", BuildPatternPayload(1024, "horrible-\u0001\u0002-\u0007-.-crypto-RedX-vKey-")),
        ("len-4096-mundane", BuildPatternPayload(4096, "mundane-rows-cols-path-walk-")),
        ("len-16384-binaryish", BuildPatternPayload(16384, "bin-\u0000\u0001\u0002\u0003-\u001B-~-repeat-"))
    };
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
void PrintSymmetricKeyInfo(RedXKey key)
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
RedXKey ResolveSymmetricKey()
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
            var key = RedX.CreateKey();
            PrintSymmetricKeyInfo(key);
            return key;
        }
        if (string.Equals(choice, "B", StringComparison.OrdinalIgnoreCase))
        {
            var blkStr = ReadRequiredCancelable("Enter block size (rows, 1-255, blank to cancel): ");
            if (blkStr == null) continue;
            if (byte.TryParse(blkStr, out var blk) && blk > 0)
            {
                var key = RedX.CreateKey(blk);
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
                var key = RedX.CreateKeyFromBytes(bytes);
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
/// Run pre-canned symmetric encrypt/decrypt pairs with the current key and print before/after info.<br/>
/// </summary>
void RunSymmetricPreset(RedXKey key, bool useIntegrity)
{
    WriteLineColor(ConsoleColor.Cyan, "=== Symmetric pre-canned cases ===");
    foreach (var (label, plain) in BuildPresetPayloads())
    {
        var ct = RedX.Encrypt(plain, key, useIntegrity);
        var ctBytes = ct.ToArray();
        var dec = RedX.Decrypt(new RedxBufferStream(ctBytes), key, useIntegrity);
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
}

/// <summary>
/// Interactive symmetric encrypt with the current key; prints plaintext/ciphertext and overhead.<br/>
/// </summary>
void SymmetricEncryptInteractive(RedXKey key, bool useIntegrity)
{
    var plain = PromptPayloadBytes("plaintext");
    if (plain == null) return;
    // new plaintext invalidates prior ciphertext
    lastSymCipherHex = null;
    var ct = RedX.Encrypt(plain, key, useIntegrity);
    var ctBytes = ct.ToArray();
    lastSymCipherHex = Convert.ToHexString(ctBytes);
    lastSymPlainHex = Convert.ToHexString(plain);
    var dec = RedX.Decrypt(new RedxBufferStream(ctBytes), key, useIntegrity);
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
void SymmetricDecryptInteractive(RedXKey key, bool requireIntegrity)
{
    var ctBytes = PromptPayloadBytes("ciphertext (hex preferred)");
    if (ctBytes == null) return;
    WriteLineColor(ConsoleColor.Cyan, "=== Symmetric decrypt ===");
    Console.WriteLine($" ciphertext: {HexWithLen(ctBytes)}");
    lastSymCipherHex = Convert.ToHexString(ctBytes);
    RedxBufferStream dec = null;
    try
    {
        dec = RedX.Decrypt(new RedxBufferStream(ctBytes), key, requireIntegrity);
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
void PrintMintingInfo(RedXMintingKey minting, RedXVerifierKey vKey)
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
void SelectMintVerifyKeys(ref RedXMintingKey minting, ref RedXVerifierKey vKey)
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
            var pair = RedX.CreateMintingKeyPair();
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
                minting = RedX.CreateMintingKey(blob);
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
                vKey = RedX.CreateVerifierKey(blob);
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
void RunMintVerifyPreset(RedXMintingKey minting, RedXVerifierKey vKey, bool useIntegrity)
{
    WriteLineColor(ConsoleColor.Cyan, "=== Mint/Verify pre-canned cases ===");
    foreach (var (label, plain) in BuildPresetPayloads())
    {
        var ct = RedX.Mint(plain, minting, useIntegrity: useIntegrity);
        var ctBytes = ct.ToArray();
        RedxBufferStream dec = null;
        try
        {
            dec = RedX.VerifyAndDecrypt(new RedxBufferStream(ctBytes), vKey, requireIntegrity: useIntegrity);
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
/// Interactive Mint/Verify mint (encrypt) with the current minting key; prints blobs and overhead.<br/>
/// </summary>
void MintInteractive(RedXMintingKey minting, RedXVerifierKey vKey, bool useIntegrity)
{
    var plain = PromptPayloadBytes("plaintext");
    if (plain == null) return;
    // new plaintext invalidates prior ciphertext snapshot
    lastMintCipherHex = null;
    var ct = RedX.Mint(plain, minting, useIntegrity: useIntegrity);
    var ctBytes = ct.ToArray();
    lastMintCipherHex = Convert.ToHexString(ctBytes);
    lastMintPlainHex = Convert.ToHexString(plain);
    RedxBufferStream dec = null;
    try
    {
        dec = RedX.VerifyAndDecrypt(new RedxBufferStream(ctBytes), vKey, requireIntegrity: useIntegrity);
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
void VerifyInteractive(RedXVerifierKey vKey, bool requireIntegrity)
{
    var ctBytes = PromptPayloadBytes("ciphertext (hex preferred)");
    if (ctBytes == null) return;
    WriteLineColor(ConsoleColor.Cyan, "=== Verify ===");
    Console.WriteLine($" ciphertext: {HexWithLen(ctBytes)}");
    lastMintCipherHex = Convert.ToHexString(ctBytes);
    RedxBufferStream dec = null;
    try
    {
        dec = RedX.VerifyAndDecrypt(new RedxBufferStream(ctBytes), vKey, requireIntegrity: requireIntegrity);
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
    RedXMintingKey minting = null;
    RedXVerifierKey verifier = null;
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
/// Entry menu for the RedX primer harness; choose symmetric or Mint/Verify flows.<br/>
/// </summary>
void RunRedXPrimer()
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
        Console.WriteLine($"  ?) {GlossaryLabel}");
        Console.WriteLine("  X) Exit");
        var choice = ReadChoiceKey("Select (S/A/?/X or ESC): ", "S", "A", "?", "X");
        if (choice == "ESC" || string.Equals(choice, "X", StringComparison.OrdinalIgnoreCase)) return;
        if (string.Equals(choice, "S", StringComparison.OrdinalIgnoreCase)) RunSymmetricMenu();
        else if (string.Equals(choice, "A", StringComparison.OrdinalIgnoreCase)) RunMintVerifyMenu();
        else if (string.Equals(choice, "?", StringComparison.OrdinalIgnoreCase)) RunGlossaryMenu(GlossaryContextMain);
    }
}

RunRedXPrimer();

class GlossaryNode
{
    public string TitleRaw { get; set; }
    public string TitleKey { get; set; }
    public int Level { get; set; }
    public GlossaryNode Parent { get; set; }
    public List<GlossaryNode> Children { get; } = new();
    public List<string> TextLines { get; } = new();
}
