using System;
using System.Security.Cryptography;
using System.IO;

namespace RedxLib
{
    /// <summary>
    /// 1-bit varint encoding/decoding helpers for core integer types.<br/>
    /// Each byte carries one data bit (bit0) and a continuation flag (bit7).<br/>
    /// Bits 1-6 are unused and may be randomized for obfuscation when requested.<br/>
    /// </summary>
    public static class Integer1BitEncodingExtensions
    {
        private const byte ContinuationMask = 0x80;
        private const byte DataMask = 0x01;
        private const byte RandomMask = 0x7E;

        /// <summary>
        /// Returns the number of bytes required to encode the value using a 1-bit varint layout.<br/>
        /// The encoding uses bit0 as data and bit7 as the continuation flag, matching the 7-bit varint ordering.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to measure.<br/></param>
        /// <returns>The number of bytes needed to encode the value.<br/></returns>
        public static int Get1BitEncodedSize(this byte value) => Get1BitEncodedSizeCore(value);

        /// <summary>
        /// Returns the number of bytes required to encode the value using a 1-bit varint layout.<br/>
        /// The encoding uses bit0 as data and bit7 as the continuation flag, matching the 7-bit varint ordering.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to measure.<br/></param>
        /// <returns>The number of bytes needed to encode the value.<br/></returns>
        public static int Get1BitEncodedSize(this ushort value) => Get1BitEncodedSizeCore(value);

        /// <summary>
        /// Returns the number of bytes required to encode the value using a 1-bit varint layout.<br/>
        /// The encoding uses bit0 as data and bit7 as the continuation flag, matching the 7-bit varint ordering.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to measure.<br/></param>
        /// <returns>The number of bytes needed to encode the value.<br/></returns>
        public static int Get1BitEncodedSize(this uint value) => Get1BitEncodedSizeCore(value);

        /// <summary>
        /// Returns the number of bytes required to encode the value using a 1-bit varint layout.<br/>
        /// The encoding uses bit0 as data and bit7 as the continuation flag, matching the 7-bit varint ordering.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to measure.<br/></param>
        /// <returns>The number of bytes needed to encode the value.<br/></returns>
        public static int Get1BitEncodedSize(this ulong value) => Get1BitEncodedSizeCore(value);

        /// <summary>
        /// Returns the number of bytes required to encode the value using a 1-bit varint layout.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to measure.<br/></param>
        /// <returns>The number of bytes needed to encode the value.<br/></returns>
        public static int Get1BitEncodedSize(this sbyte value) => Get1BitEncodedSizeCore(EnsureNonNegative(value, nameof(value)));

        /// <summary>
        /// Returns the number of bytes required to encode the value using a 1-bit varint layout.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to measure.<br/></param>
        /// <returns>The number of bytes needed to encode the value.<br/></returns>
        public static int Get1BitEncodedSize(this short value) => Get1BitEncodedSizeCore(EnsureNonNegative(value, nameof(value)));

        /// <summary>
        /// Returns the number of bytes required to encode the value using a 1-bit varint layout.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to measure.<br/></param>
        /// <returns>The number of bytes needed to encode the value.<br/></returns>
        public static int Get1BitEncodedSize(this int value) => Get1BitEncodedSizeCore(EnsureNonNegative(value, nameof(value)));

        /// <summary>
        /// Returns the number of bytes required to encode the value using a 1-bit varint layout.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to measure.<br/></param>
        /// <returns>The number of bytes needed to encode the value.<br/></returns>
        public static int Get1BitEncodedSize(this long value) => Get1BitEncodedSizeCore(EnsureNonNegative(value, nameof(value)));

        /// <summary>
        /// Encodes the value as a 1-bit varint and returns a new byte array.<br/>
        /// The encoding uses bit0 as data and bit7 as the continuation flag, matching the 7-bit varint ordering.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>A new byte array containing the encoded value.<br/></returns>
        public static byte[] To1BitEncodedBytes(this byte value, bool randomizeUnusedBits = false)
        {
            int size = Get1BitEncodedSizeCore(value);
            var buffer = new byte[size];
            Write1BitEncodedCore(value, buffer, randomizeUnusedBits);
            return buffer;
        }

        /// <summary>
        /// Encodes the value as a 1-bit varint and returns a new byte array.<br/>
        /// The encoding uses bit0 as data and bit7 as the continuation flag, matching the 7-bit varint ordering.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>A new byte array containing the encoded value.<br/></returns>
        public static byte[] To1BitEncodedBytes(this ushort value, bool randomizeUnusedBits = false)
        {
            int size = Get1BitEncodedSizeCore(value);
            var buffer = new byte[size];
            Write1BitEncodedCore(value, buffer, randomizeUnusedBits);
            return buffer;
        }

        /// <summary>
        /// Encodes the value as a 1-bit varint and returns a new byte array.<br/>
        /// The encoding uses bit0 as data and bit7 as the continuation flag, matching the 7-bit varint ordering.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>A new byte array containing the encoded value.<br/></returns>
        public static byte[] To1BitEncodedBytes(this uint value, bool randomizeUnusedBits = false)
        {
            int size = Get1BitEncodedSizeCore(value);
            var buffer = new byte[size];
            Write1BitEncodedCore(value, buffer, randomizeUnusedBits);
            return buffer;
        }

        /// <summary>
        /// Encodes the value as a 1-bit varint and returns a new byte array.<br/>
        /// The encoding uses bit0 as data and bit7 as the continuation flag, matching the 7-bit varint ordering.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>A new byte array containing the encoded value.<br/></returns>
        public static byte[] To1BitEncodedBytes(this ulong value, bool randomizeUnusedBits = false)
        {
            int size = Get1BitEncodedSizeCore(value);
            var buffer = new byte[size];
            Write1BitEncodedCore(value, buffer, randomizeUnusedBits);
            return buffer;
        }

        /// <summary>
        /// Encodes the value as a 1-bit varint and returns a new byte array.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to encode.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>A new byte array containing the encoded value.<br/></returns>
        public static byte[] To1BitEncodedBytes(this sbyte value, bool randomizeUnusedBits = false)
        {
            ulong unsigned = EnsureNonNegative(value, nameof(value));
            int size = Get1BitEncodedSizeCore(unsigned);
            var buffer = new byte[size];
            Write1BitEncodedCore(unsigned, buffer, randomizeUnusedBits);
            return buffer;
        }

        /// <summary>
        /// Encodes the value as a 1-bit varint and returns a new byte array.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to encode.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>A new byte array containing the encoded value.<br/></returns>
        public static byte[] To1BitEncodedBytes(this short value, bool randomizeUnusedBits = false)
        {
            ulong unsigned = EnsureNonNegative(value, nameof(value));
            int size = Get1BitEncodedSizeCore(unsigned);
            var buffer = new byte[size];
            Write1BitEncodedCore(unsigned, buffer, randomizeUnusedBits);
            return buffer;
        }

        /// <summary>
        /// Encodes the value as a 1-bit varint and returns a new byte array.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to encode.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>A new byte array containing the encoded value.<br/></returns>
        public static byte[] To1BitEncodedBytes(this int value, bool randomizeUnusedBits = false)
        {
            ulong unsigned = EnsureNonNegative(value, nameof(value));
            int size = Get1BitEncodedSizeCore(unsigned);
            var buffer = new byte[size];
            Write1BitEncodedCore(unsigned, buffer, randomizeUnusedBits);
            return buffer;
        }

        /// <summary>
        /// Encodes the value as a 1-bit varint and returns a new byte array.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to encode.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>A new byte array containing the encoded value.<br/></returns>
        public static byte[] To1BitEncodedBytes(this long value, bool randomizeUnusedBits = false)
        {
            ulong unsigned = EnsureNonNegative(value, nameof(value));
            int size = Get1BitEncodedSizeCore(unsigned);
            var buffer = new byte[size];
            Write1BitEncodedCore(unsigned, buffer, randomizeUnusedBits);
            return buffer;
        }

        /// <summary>
        /// Encodes the value into the provided destination as a 1-bit varint.<br/>
        /// The destination span must be at least Get1BitEncodedSize(value) bytes long.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        public static int Write1BitEncoded(this byte value, Span<byte> destination, bool randomizeUnusedBits = false)
        {
            return Write1BitEncodedCore(value, destination, randomizeUnusedBits);
        }

        /// <summary>
        /// Encodes the value into the provided destination as a 1-bit varint.<br/>
        /// The destination span must be at least Get1BitEncodedSize(value) bytes long.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        public static int Write1BitEncoded(this ushort value, Span<byte> destination, bool randomizeUnusedBits = false)
        {
            return Write1BitEncodedCore(value, destination, randomizeUnusedBits);
        }

        /// <summary>
        /// Encodes the value into the provided destination as a 1-bit varint.<br/>
        /// The destination span must be at least Get1BitEncodedSize(value) bytes long.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        public static int Write1BitEncoded(this uint value, Span<byte> destination, bool randomizeUnusedBits = false)
        {
            return Write1BitEncodedCore(value, destination, randomizeUnusedBits);
        }

        /// <summary>
        /// Encodes the value into the provided destination as a 1-bit varint.<br/>
        /// The destination span must be at least Get1BitEncodedSize(value) bytes long.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        public static int Write1BitEncoded(this ulong value, Span<byte> destination, bool randomizeUnusedBits = false)
        {
            return Write1BitEncodedCore(value, destination, randomizeUnusedBits);
        }

        /// <summary>
        /// Encodes the value into the provided destination as a 1-bit varint.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        public static int Write1BitEncoded(this sbyte value, Span<byte> destination, bool randomizeUnusedBits = false)
        {
            return Write1BitEncodedCore(EnsureNonNegative(value, nameof(value)), destination, randomizeUnusedBits);
        }

        /// <summary>
        /// Encodes the value into the provided destination as a 1-bit varint.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        public static int Write1BitEncoded(this short value, Span<byte> destination, bool randomizeUnusedBits = false)
        {
            return Write1BitEncodedCore(EnsureNonNegative(value, nameof(value)), destination, randomizeUnusedBits);
        }

        /// <summary>
        /// Encodes the value into the provided destination as a 1-bit varint.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        public static int Write1BitEncoded(this int value, Span<byte> destination, bool randomizeUnusedBits = false)
        {
            return Write1BitEncodedCore(EnsureNonNegative(value, nameof(value)), destination, randomizeUnusedBits);
        }

        /// <summary>
        /// Encodes the value into the provided destination as a 1-bit varint.<br/>
        /// Negative values are rejected and will throw.<br/>
        /// </summary>
        /// <param name="value">The signed value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        public static int Write1BitEncoded(this long value, Span<byte> destination, bool randomizeUnusedBits = false)
        {
            return Write1BitEncodedCore(EnsureNonNegative(value, nameof(value)), destination, randomizeUnusedBits);
        }

        /// <summary>
        /// Decodes a 1-bit varint from the provided data and returns the value.<br/>
        /// The method reports how many bytes were consumed via the bytesRead out parameter.<br/>
        /// </summary>
        /// <param name="data">The data containing the 1-bit encoded value.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded unsigned value.<br/></returns>
        public static byte Read1BitEncodedByte(this ReadOnlySpan<byte> data, out int bytesRead)
        {
            ulong value = Read1BitEncodedCore(data, 8, out bytesRead);
            if (value > byte.MaxValue) throw new OverflowException("Decoded value exceeds Byte.MaxValue.");
            return (byte)value;
        }

        /// <summary>
        /// Decodes a 1-bit varint from the provided data and returns the value.<br/>
        /// The method reports how many bytes were consumed via the bytesRead out parameter.<br/>
        /// </summary>
        /// <param name="data">The data containing the 1-bit encoded value.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded unsigned value.<br/></returns>
        public static ushort Read1BitEncodedUInt16(this ReadOnlySpan<byte> data, out int bytesRead)
        {
            ulong value = Read1BitEncodedCore(data, 16, out bytesRead);
            if (value > ushort.MaxValue) throw new OverflowException("Decoded value exceeds UInt16.MaxValue.");
            return (ushort)value;
        }

        /// <summary>
        /// Decodes a 1-bit varint from the provided data and returns the value.<br/>
        /// The method reports how many bytes were consumed via the bytesRead out parameter.<br/>
        /// </summary>
        /// <param name="data">The data containing the 1-bit encoded value.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded unsigned value.<br/></returns>
        public static uint Read1BitEncodedUInt32(this ReadOnlySpan<byte> data, out int bytesRead)
        {
            ulong value = Read1BitEncodedCore(data, 32, out bytesRead);
            if (value > uint.MaxValue) throw new OverflowException("Decoded value exceeds UInt32.MaxValue.");
            return (uint)value;
        }

        /// <summary>
        /// Decodes a 1-bit varint from the provided data and returns the value.<br/>
        /// The method reports how many bytes were consumed via the bytesRead out parameter.<br/>
        /// </summary>
        /// <param name="data">The data containing the 1-bit encoded value.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded unsigned value.<br/></returns>
        public static ulong Read1BitEncodedUInt64(this ReadOnlySpan<byte> data, out int bytesRead)
        {
            return Read1BitEncodedCore(data, 64, out bytesRead);
        }

        /// <summary>
        /// Decodes a 1-bit varint from the provided data and returns the value.<br/>
        /// The method reports how many bytes were consumed via the bytesRead out parameter.<br/>
        /// </summary>
        /// <param name="data">The data containing the 1-bit encoded value.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded signed value.<br/></returns>
        public static sbyte Read1BitEncodedSByte(this ReadOnlySpan<byte> data, out int bytesRead)
        {
            ulong value = Read1BitEncodedCore(data, 7, out bytesRead);
            if (value > (ulong)sbyte.MaxValue) throw new OverflowException("Decoded value exceeds SByte.MaxValue.");
            return (sbyte)value;
        }

        /// <summary>
        /// Decodes a 1-bit varint from the provided data and returns the value.<br/>
        /// The method reports how many bytes were consumed via the bytesRead out parameter.<br/>
        /// </summary>
        /// <param name="data">The data containing the 1-bit encoded value.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded signed value.<br/></returns>
        public static short Read1BitEncodedInt16(this ReadOnlySpan<byte> data, out int bytesRead)
        {
            ulong value = Read1BitEncodedCore(data, 15, out bytesRead);
            if (value > (ulong)short.MaxValue) throw new OverflowException("Decoded value exceeds Int16.MaxValue.");
            return (short)value;
        }

        /// <summary>
        /// Decodes a 1-bit varint from the provided data and returns the value.<br/>
        /// The method reports how many bytes were consumed via the bytesRead out parameter.<br/>
        /// </summary>
        /// <param name="data">The data containing the 1-bit encoded value.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded signed value.<br/></returns>
        public static int Read1BitEncodedInt32(this ReadOnlySpan<byte> data, out int bytesRead)
        {
            ulong value = Read1BitEncodedCore(data, 31, out bytesRead);
            if (value > int.MaxValue) throw new OverflowException("Decoded value exceeds Int32.MaxValue.");
            return (int)value;
        }

        /// <summary>
        /// Decodes a 1-bit varint from the provided data and returns the value.<br/>
        /// The method reports how many bytes were consumed via the bytesRead out parameter.<br/>
        /// </summary>
        /// <param name="data">The data containing the 1-bit encoded value.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded signed value.<br/></returns>
        public static long Read1BitEncodedInt64(this ReadOnlySpan<byte> data, out int bytesRead)
        {
            ulong value = Read1BitEncodedCore(data, 63, out bytesRead);
            if (value > long.MaxValue) throw new OverflowException("Decoded value exceeds Int64.MaxValue.");
            return (long)value;
        }

        /// <summary>
        /// Ensures a signed input is non-negative and returns it as an unsigned value.<br/>
        /// Throws when the value is negative.<br/>
        /// </summary>
        /// <param name="value">The signed value to validate.<br/></param>
        /// <param name="paramName">The parameter name for exception reporting.<br/></param>
        /// <returns>The unsigned representation of the value.<br/></returns>
        private static ulong EnsureNonNegative(long value, string paramName)
        {
            if (value < 0) throw new ArgumentOutOfRangeException(paramName, "Value must be non-negative.");
            return (ulong)value;
        }

        /// <summary>
        /// Computes the number of bytes required for a 1-bit varint encoding.<br/>
        /// Returns at least 1 even when the value is zero.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to measure.<br/></param>
        /// <returns>The number of bytes required to encode the value.<br/></returns>
        private static int Get1BitEncodedSizeCore(ulong value)
        {
            int count = 1;
            while (value >= 2)
            {
                value >>= 1;
                count++;
            }
            return count;
        }

        /// <summary>
        /// Writes a 1-bit varint into the destination span.<br/>
        /// Bits 1-6 are either zeroed or randomized depending on the flag.<br/>
        /// </summary>
        /// <param name="value">The unsigned value to encode.<br/></param>
        /// <param name="destination">The destination span to write into.<br/></param>
        /// <param name="randomizeUnusedBits">If true, random bits are injected into bits1-6 for obfuscation.<br/></param>
        /// <returns>The number of bytes written to the destination.<br/></returns>
        private static int Write1BitEncodedCore(ulong value, Span<byte> destination, bool randomizeUnusedBits)
        {
            int count = Get1BitEncodedSizeCore(value);
            if (destination.Length < count)
                throw new ArgumentException("Destination span is too small.", nameof(destination));

            byte[] randomBytes = null;
            if (randomizeUnusedBits)
            {
                randomBytes = new byte[count];
                RandomNumberGenerator.Fill(randomBytes);
            }

            for (int i = 0; i < count; i++)
            {
                byte b = (byte)(value & DataMask);
                value >>= 1;
                if (i < count - 1)
                    b |= ContinuationMask;
                if (randomizeUnusedBits)
                    b |= (byte)(randomBytes[i] & RandomMask);
                destination[i] = b;
            }

            return count;
        }

        /// <summary>
        /// Reads a 1-bit varint from the provided data span.<br/>
        /// The method enforces a maximum bit width to avoid overflow.<br/>
        /// </summary>
        /// <param name="data">The data containing the encoded value.<br/></param>
        /// <param name="bitWidth">The maximum number of bits allowed for the target type.<br/></param>
        /// <param name="bytesRead">The number of bytes consumed from data.<br/></param>
        /// <returns>The decoded unsigned value.<br/></returns>
        private static ulong Read1BitEncodedCore(ReadOnlySpan<byte> data, int bitWidth, out int bytesRead)
        {
            if (data.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(data), "Not enough bytes to decode a 1-bit encoded value.");

            ulong result = 0;
            int shift = 0;
            int index = 0;

            while (true)
            {
                if (index >= data.Length)
                    throw new ArgumentOutOfRangeException(nameof(data), "Not enough bytes to decode a 1-bit encoded value.");

                if (shift >= bitWidth)
                    throw new OverflowException("Decoded value exceeds the target type's maximum size.");

                byte b = data[index++];
                if ((b & DataMask) != 0)
                    result |= 1UL << shift;

                if ((b & ContinuationMask) == 0)
                    break;

                shift++;
            }

            bytesRead = index;
            int minimal = Get1BitEncodedSizeCore(result);
            if (bytesRead != minimal)
                throw new InvalidDataException("Non-canonical 1-bit encoding: length exceeds minimal size.");
            return result;
        }
    }
}
