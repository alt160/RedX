Learn more / Glossary of terms
	Primer intro
		RedX is an experimental [[path-walking]] cipher intended for analysis and review only.
		A [[RedX key]] is 2 or more rows (blocks) of 256-byte randomized permutations.
		Encryption uses an internal [[Jump stream]] and outputs a stream of [[key-row offset values]] as ciphertext.
		It is not production-ready and must not be used in security-critical systems.
		Ciphertext is the recording of jumps and distances between bytes across the key; decryption replays that walk to recover plaintext.
		This primer focuses on usage and capability boundaries; construction details are in the source code.
	Anti-symmetric intro
		[[Anti-symmetric mode]] in RedX refers to separate and distinct capabilities between encryption and decryption.
		This mode produces a key pair with 2 distinct roles: a <<minting key>> and a <<verifier key>>.
		The <<minting key>> can create valid ciphertexts; the <<verifier key>> can only decrypt and verify them.
		The roles are intentionally inverted: the <<verifier key>> can decrypt and verifies that the ciphertext was minted by its paired <<minting key>>.
		If verification fails, no output is produced.
		The <<minting key>> creates ciphertexts and emits a signed traversal transcript (a record of work performed, not plaintext or ciphertext).
		The signing of the transcript uses standard asymmetric cryptograpic signature primitives.
		Verification uses that primitive to validate the transcript that is reproduced during decryption.
		This is a capability policy enforced by the [[path-walking]] construction and encoded traversal metadata.
		[[Anti-symmetric mode]] behavior is not a cryptographic bar on encrypting what you can decrypt; it is a capability lock that prevents ciphertext minted without the paired <<minting key>> from validating.
		Authority here is embedded in the minting/verifier keypair, not an external authority.
	Core design: path-walking
		RedX uses an internal [[Jump stream]] to drive a walk thru a <<RedX key>>.
		The <<landing byte value>> after a jump is used to calculate <<key-row offset value>>.
		Ciphertext is the stream of <<key-row offset values>>, not the [[Jump stream]].
		Decryption regenerates the [[Jump stream]] and replays the walk and offsets to recover plaintext bytes.
		This [[path-walking]] design is the core security mechanism of RedX.
	Jump stream
		[[Jump stream]] is the internal sequence of row/col jumps produced by a cryptographic pseudorandom generator.
		The uniqueness of the jump stream is the result of its traversal thru a <<RedX key>> and influenced by the [[random start location]] and the [[Interference catalyst]] for each execution.
		The [[jump stream]] is not stored in ciphertext and cannot be derived or calculated from ciphertext alone.
		It exists only during execution to drive landing positions within a <<RedX key>>.
	Key-row offset value
		A [[Key-row offset value]] is the wrapped distance (0 to 255) from each landing byte to the byte matching the next plaintext byte in the same key row.
		It is the ciphertext payload written to the wire.
		It varies per execution as a result of the [[Random Start Location]] and [[Interference catalyst]] length.
		Decryption regenerates the [[Jump stream]] and applies inverts the offsets to recover plaintext.
	Interference catalyst
		[[Interference catalyst]] is a per-execution value of random bytes of random length from a true random source.
		It is encrypted in the ciphertext header and mixed into the [[Jump stream]].
		It seeds the pseudorandom jump generator and binds the authentication seal.
		It is unique per execution, even for the same key and same plaintext.
		It forces divergent traversals across repeated inputs.
	Random Start Location
		[[Random Start Location]] is the per-execution origin of the walk within a <<RedX key>>.
		It is encrypted in the header and selects the payload path.
		It prevents fixed-position leakage and keeps output non-repeatable and is another source of interference for the [[Jump stream]].
		It separates header mapping from payload mapping.
	Ciphertext production
		How ciphertext is produced
			Ciphertext is produced by a traversal thru a <<RedX key>>; the output is a stream of [[Key-row offset values]].
			Header fields are mapped at fixed positions (pos-0 or [[Interference catalyst]] length).
			Payload is mapped from a [[Random Start Location]].
			The [[Jump stream]] is internal and not written to ciphertext.
			No plaintext bytes are stored or signed directly.
			[[Anti-symmetric mode]] signs the traversal transcript, not plaintext.
		Why the result is unique
			Ciphertext encodes indirect movement across a permutation, not substituted bytes.
			[[Random Start Location]] and [[Interference catalyst]] change per execution, even for the same key and same plaintext.
			The [[Key-row offset values]] depend on the internal [[Jump stream]] and header inputs.
			Traversal and mapping are coupled; there is no static block transform.
			This yields an indirect non-linear relation between input, key, and output.
	Plaintext size & performance
		Per-byte cost is constant; total cost scales linearly with size.
		Overhead is fixed per message, not per byte.
		The security profile is size-agnostic within the design.
		No additional guarantees are claimed for larger inputs.
	Key sizing & variability
		Minimum and default sizes
			Key size equals the number of 256-byte rows in the permutation grid.
			Minimum safe size: 2 blocks (512 bytes).
			Default in the demo: 8 blocks (2048 bytes).
			Recompiling of the algorithm is not required to create or use a different key size.
		Large keys and performance
			Per-byte cost is constant across key sizes.
			A 1MB key performs similarly to a 512-byte key.
			Large keys increase state, not per-byte work.
			Use larger keys when storage and transport allow.
	Authentication mode
		What it is
			[[Authentication mode]] adds an authentication seal over [[Key-row offset values]] + [[Interference catalyst]] (ciphertext).
			The seal is unique per execution, even for the same key and same plaintext.
			When enabled, decrypt requires a valid seal.
			Missing or invalid seals return null.
			This provides tamper/corruption detection without releasing plaintext.
			This is distinct from authority checkpoints in [[Anti-symmetric mode]].
		Why it works
			Any change to [[Key-row offset values]] or [[Interference catalyst]] changes the seal.
			The seal is mapped under the same keying as the payload.
			This binds integrity to the walk, not to plaintext bytes.
		Relation to anti-symmetric mode
			[[Authentication mode]] is symmetric integrity only (tamper/corruption detection).
			[[Anti-symmetric mode]] is a capability model (mint vs verify).
			They can be used together: [[Anti-symmetric mode]] + authentication seal.
	RedX Keys
		Core concepts (lowest detail first)
			Permutation grid: N rows of 256-byte permutations (values 0–255).
			Key hash: derived from the permutation grid (not stored in blobs).
			Derivation seed: optional input used to deterministically rebuild verifier maps.
			Authority keypair: signing keys used only in anti-symmetric mode.
		Symmetric keys
			Runtime composition (in-memory)
				Full key: permutation grid + key hash + derived tables.
			Serialized blob (on disk / wire)
				Version + key length + raw permutation bytes.
			How symmetric keys are produced
				Generated from entropy, or from a caller-provided seed if used.
				Rehydrated by loading the blob and recomputing derived state.
		Anti-symmetric keys
			Minting key runtime composition
				Full symmetric key + authority signing keypair.
			Minting key serialized blob
				Symmetric key blob + authority private/public keypair.
			Verifier key runtime composition
				vKey core: key hash + derived nonces/map + authority public key.
				The permutation grid is not retained at runtime.
			Verifier key serialized blob
				vKey blob: seed + raw permutation bytes + authority public key.
			How anti-symmetric keys are produced
				Minting key is generated from entropy (or seed) plus a new authority keypair.
				vKey is derived from the minting key or imported as a blob.
		General lifecycle notes
			Treat all key blobs as secrets; protect at rest and in transit.
			vKey can be shared without minting material.
	Ciphertext: contains / does not contain
		Contains: encrypted header, [[Key-row offset stream]], optional authentication seal.
		[[Anti-symmetric mode]] includes signed traversal transcript (checkpoints).
		The [[Jump stream]] is internal and not stored.
		Does not contain plaintext or direct plaintext transforms.
		Does not contain the key or permutation.
	Anti-symmetric mode
		Why the name
			[[Anti-symmetric mode]] refers to inverted capabilities, not asymmetric encryption.
			Verifier decrypts and verifies; minter encrypts and mints.
			Verifier cannot mint valid ciphertexts.
		Use cases
			Software licensing and delegated read access.
			Escrowed decryption with provenance.
			Controlled distribution where minting is centralized.
		What it cannot do
			Verifier cannot mint new valid ciphertexts.
			Not a signature scheme or general-purpose PKI.
			Requires authority key for provenance validation.
		Authority terminology
			Authority is embedded in the minting/verifier keypair.
			It is not an external service or trusted third party.
			Checkpoints sign traversal state, not plaintext.
	Claims & non-claims
		Security strength not yet determined; no formal proof or independent audit.
		This release is intended to begin formal analysis and proof work.
		PAI here means post-AI cryptanalysis (AI/ML-aided cryptanalysis).
		Not claiming post-quantum or post-AI (PAI) resistance.
		Not yet analyzed against standard cryptanalysis families; public analysis invited.
	Failure semantics
		Authentication failure returns null.
		Authority verification failure returns null.
		No plaintext is emitted on failure.
	Wire format
		Physical vs logical structure
			Physical layout is a byte stream with minimal framing.
			Only [[Interference catalyst]] length (and rokLock in [[Anti-symmetric mode]]) are plaintext; other fields are mapped.
			Logical structure appears in two phases:
			1) decode control fields at fixed positions,
			2) decode payload from a [[Random Start Location]] into a [[Key-row offset stream]].
			Intuition: fixed + random mapping creates an interference pattern across the walk.
		Symmetric layout
			Symmetric (authentication off): enc(startLoc) | intCatLen | enc(intCat) | [[Key-row offset stream]]
			Symmetric (authentication on):  enc(startLoc) | intCatLen | enc(intCat) | [[Key-row offset stream]] | enc(seal)
			[[Random Start Location]] is mapped at pos-0; [[Interference catalyst]] is mapped at pos-intCatLen.
			Payload [[Key-row offset stream]] is mapped from the [[Random Start Location]].
		Anti-symmetric layout
			[[Anti-symmetric mode]] (authentication off): rokLock | enc(startLoc) | enc(ckCount) | enc(sigs) | intCatLen | enc(intCat) | [[Key-row offset stream]]
			[[Anti-symmetric mode]] (authentication on):  rokLock | enc(startLoc) | enc(ckCount) | enc(sigs) | intCatLen | enc(intCat) | [[Key-row offset stream]] | enc(seal)
			Control stream is ROK-mapped using rokLock at pos-0.
		Header fields and roles
			rokLock: per-message binder for control stream mapping.
			[[Random Start Location]]: encrypted at pos-0; selects payload walk origin.
			[[Interference catalyst]]: encrypted at pos-intCatLen; mixes into mapping for replay resistance.
			In [[Anti-symmetric mode]], [[Random Start Location]] is mapped under rokLock for verifier recovery.
			rokLock remains plaintext to bootstrap header decode.