Cleanup tasks

RedXLib/RedX.cs
- CreateKeyFromHex (line 226) --done
- DecryptAntiSym (line 555) --done
- DecryptVerified (line 817) --done
- RedXMintingKey.AuthorityPrivateKey (line 2156) --done
- REKey.FromHex (line 1891) // todo added
- RLE.EncodeUShortRuns (line 1952) // todo added
- RLE.DecodeUShortRuns (line 1993) // todo added

RedXLib/Blake3XofReader.cs
- Blake3XofReader.ReadNextOf<T> (line 102) --done
- Blake3XofReader.ReadNextOfInto<T> (line 108) --done
- Blake3XofReader.ReadNext(Span<ushort>) (line 116) --done
- Blake3XofReader.ReadNext(Span<uint>) (line 123) --done
- Blake3XofReader.ReadNext(Span<short>) (line 130) --done
- Blake3XofReader.ReadNext(Span<int>) (line 137) --done
- Blake3XofReader.ReadNext(Span<Guid>) (line 144) --done
- JumpGenerator.NextJump32 (line 202) --done

RedXLib/BufferStream.cs
- AsReadOnlyMemory (line 162)
- AsWritableSpan (line 186)
- Flush (line 490)
- Read7BitInt (line 521)
- ReadAtOffset (line 546)
- ReadBytesWithLength (line 580)
- ReadChar (line 582)
- ReadDateOnly (line 584)
- ReadDateTime (line 586)
- ReadDecimal (line 588)
- ReadDouble (line 590)
- ReadGuid (line 592)
- ReadInt16 (line 594)
- ReadInt32 (line 596)
- ReadSingle (line 639)
- ReadString (line 641)
- ReadTimeOnly (line 650)
- ReadTimeSpan (line 656)
- ReadUInt32 (line 664)
- ReadUInt64 (line 666)
- Reset (line 675)
- Seek (line 687)
- SetLength (line 708)
- Write7BitUInt (line 782)
- WriteableSpan (line 811)
- WriteBooleansWithLength (line 890)
- WriteDateTimesWithLength (line 955)
- WriteDoublesWithLength (line 957)
- WriteFloatsWithLength (line 959)
- WriteGuidsWithLength (line 961)
- WriteIntsWithLength (line 963)
- WriteLongsWithLength (line 965)
- WriteSBytesWithLength (line 967)
- WriteShortsWithLength (line 969)
- WriteTimespansWithLength (line 971)
- WriteUIntsWithLength (line 973)
- WriteULongsWithLength (line 975)
- WriteUShortsWithLength (line 977)

RedXLib/Integer1BitEncodingExtensions.cs (unused overloads; only To1BitEncodedBytes(ushort) and Read1BitEncodedUInt16 are referenced)
- Get1BitEncodedSize: byte, ushort, uint, ulong, sbyte, short, int, long (lines 24‑80)
- To1BitEncodedBytes: byte, uint, ulong, sbyte, short, int, long (lines 89‑197)
- Write1BitEncoded: byte, ushort, uint, ulong, sbyte, short, int, long (lines 214‑305)
- Read1BitEncoded*: Byte, UInt32, UInt64, SByte, Int16, Int32, Int64 (lines 317‑413)

Dead‑file public surface (also unused in repo)
- RedXLib/CbeSigner.cs: CbeSigner (ctor, Sign, Verify, static Verify, GenerateRandomKey), XorHashAsymmetricCipher (ctor, EncryptByte, DecryptByte, Encrypt, Decrypt) --done
- RedXLib/HmacDrbg.cs: HmacDrbg (ctor, Reseed, Generate overloads, Dispose) --done
- RedXLib/IVrfVerifier.cs: IVrfVerifier.Verify --done
- RedXLib/Universe.cs: SyntheticCurve (ctor, Generator, Associate, Ambulate, PureAssociate), SyntheticSignature, SignatureScheme (GenerateKeyPair, Sign, Verify), Program.Main --done
- RedXLib/IChameleonHash.cs + RedXLib/SimpleChameleonHash.cs: IChameleonHash (PublicParam, Compute, Invert), SmallPrimeChameleon (CreateWithTrapdoor, CreateFromPublicParam, PublicParam, Compute overloads, Invert) --done
