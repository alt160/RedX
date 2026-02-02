using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RobinsonEncryptionLib
{
    public static class RE
    {

        public static REKey CreateKey()
        {
            return new REKey();
        }

        public static byte[] Encrypt(byte[] data, REKey keyA, REKey keyB)
        {
            var e1 = keyA.DrawPath(data.AsSpan());


            var aStar = new BufferStream();

            // write l3 count to aStar
            aStar.Write7BitEncodedInt(e1.kStar.Count);

            // build bytes of used values from keyA
            foreach (var kv in e1.kStar)
            {
                aStar.Write(kv.Key);
                aStar.Write7BitEncodedInt(kv.Value);
            }

            // encrypt aStar with keyB
            var aStarEnc = keyB.DrawPath(aStar.AsReadOnlySpan);


            // cross map skip indexes thru keyB to get encrypted data
            var encData = keyB.FollowPath(e1.skips);

            // combine aStar and encData for return
            var result = new BufferStream();
            result.WriteBytes(aStarEnc.skips.ToArray());
            result.Write(encData.ToArray());

            return result.ToArray();


        }

        public static byte[] Decrypt(byte[] cipher,REKey keyA, REKey keyB)
        {
            
        }

    }

    public class REKey
    {
        internal Memory<byte> key;
        internal Dictionary<byte, short[]> rkd;

        public REKey(byte keySize = 8)
        {
            if(keySize < 2)
                throw new ArgumentException("Key size must be at least 2", nameof(keySize));
            var keyData = new BufferStream();
            rkd = new Dictionary<byte, short[]>(keySize * 256);

            var idx = (short)0;
            for (int i = 0; i < keySize; i++)
            {
                var array = new byte[256];
                var span = array.AsSpan();
                for (byte a = 0; a < span.Length; a++)
                {
                    rkd[a] = new short[keySize];
                    span[a] = a;
                }



                Shuffle(array.AsSpan());
                for (int j = 0; j < span.Length; j++)
                {
                    keyData.Write(span[j]);
                }
            }
        }

        internal (BufferStream skips, Dictionary<byte, short> kStar) DrawPath(ReadOnlySpan<byte> data)
        {
            var l1 = new BufferStream();
            var l3 = new Dictionary<byte, short>(256);

            var sl = (short)RandomNumberGenerator.GetInt32(0, data.Length);

            l1.Write(sl);

            for (int i = 0; i < data.Length; i++)
            {
                // choose a random index from the keyA dictionary
                var z = RandomNumberGenerator.GetInt32(0, rkd[data[i]].Length);
                var ix = rkd[data[i]][z];

                // Calculate shortest absolute distance between current location (sl) and ix
                // with support for wrap-around if that's the shortest path
                int directDistance = Math.Abs(ix - sl);
                int wrapDistance = data.Length - directDistance;
                int shortestDistance = Math.Min(directDistance, wrapDistance);

                // Determine the sign (direction)
                short d;
                if (directDistance <= wrapDistance)
                {
                    // Direct path is shorter or equal
                    d = (short)(ix >= sl ? directDistance : -directDistance);
                }
                else
                {
                    // Wrap-around path is shorter
                    d = (short)(ix >= sl ? -wrapDistance : wrapDistance);
                }

                l3[data[i]] = (short)d;
                // write skip distance to l1
                l1.Write((short)d);

            }
            l1.Position = 0;
            return (l1, l3);

        }

        internal BufferStream SkipsFromBytes(byte[] bytes) {
            var result = new BufferStream();

            foreach (var b in bytes)
            {

            }

        }


        internal BufferStream FollowPath(BufferStream skips)
        {
            var result = new BufferStream();
            skips.Position = 0;

            // Read the starting position
            short currentPos = skips.ReadInt16();

            // Follow the skip distances until we reach the end of the stream
            while (skips.Position < skips.Length)
            {
                try
                {
                    // Read the next skip distance
                    short skip = skips.ReadInt16();

                    // Apply the skip to the current position, handling wrap-around
                    currentPos = (short)((currentPos + skip + key.Length) % key.Length);

                    // Get the byte at this position in the key
                    result.Write(key.Span[currentPos]);
                }
                catch (EndOfStreamException)
                {
                    // We've reached the end of the stream
                    break;
                }
            }

            result.Position = 0;
            return result;
        }


        /// <summary>
        /// Performs a Fisher-Yates shuffle on a Memory<byte>
        /// </summary>
        /// <param name="memory">The memory to shuffle</param>
        /// <param name="random">Optional random number generator (uses cryptographically secure RNG if null)</param>
        public static void Shuffle (Memory<byte> memory, Random? random = null)
        {
            if (memory.IsEmpty || memory.Length <= 1)
                return;

            // Get a span for direct access
            Span<byte> span = memory.Span;

            // Use cryptographically secure random if none provided
            bool useSecureRandom = random == null;

            // Fisher-Yates shuffle algorithm
            for (int i = span.Length - 1; i > 0; i--)
            {
                // Generate a random index between 0 and i (inclusive)
                int j;
                if (useSecureRandom)
                    j = RandomNumberGenerator.GetInt32(i + 1);
                else
                    j = random!.Next(i + 1);

                // Swap elements at i and j
                byte temp = span[i];
                span[i] = span[j];
                span[j] = temp;
            }
        }

        /// <summary>
        /// Performs a Fisher-Yates shuffle on a Memory<byte>
        /// </summary>
        /// <param name="memory">The memory to shuffle</param>
        /// <param name="random">Optional random number generator (uses cryptographically secure RNG if null)</param>
        public static void Shuffle (Span<byte> span, Random? random = null)
        {
            if (span.IsEmpty || span.Length <= 1)
                return;

 
            // Use cryptographically secure random if none provided
            bool useSecureRandom = random == null;

            // Fisher-Yates shuffle algorithm
            for (int i = span.Length - 1; i > 0; i--)
            {
                // Generate a random index between 0 and i (inclusive)
                int j;
                if (useSecureRandom)
                    j = RandomNumberGenerator.GetInt32(i + 1);
                else
                    j = random!.Next(i + 1);

                // Swap elements at i and j
                byte temp = span[i];
                span[i] = span[j];
                span[j] = temp;
            }
        }


        /// <summary>
        /// Performs a Fisher-Yates shuffle on a byte array
        /// </summary>
        /// <param name="array">The array to shuffle</param>
        /// <param name="random">Optional random number generator (uses cryptographically secure RNG if null)</param>
        private static void Shuffle (byte[] array, Random? random = null)
        {
            if (array == null || array.Length <= 1)
                return;

            // Use cryptographically secure random if none provided
            bool useSecureRandom = random == null;

            // Fisher-Yates shuffle algorithm
            for (int i = array.Length - 1; i > 0; i--)
            {
                // Generate a random index between 0 and i (inclusive)
                int j;
                if (useSecureRandom)
                    j = RandomNumberGenerator.GetInt32(i + 1);
                else
                    j = random!.Next(i + 1);

                // Swap elements at i and j
                byte temp = array[i];
                array[i] = array[j];
                array[j] = temp;
            }
        }
    }

    public sealed class BufferStream : Stream
    {








        // Helper: Calculate size of 7-bit encoded int
        //Shared/Static Members
        private static int Get7BitEncodedIntSize(int value)
        {
            int count = 0;
            uint v = (uint)value;
            do
            {
                v >>= 7;
                count++;
            } while (v != 0);
            return count;
        }
        // Helper: Write 7-bit encoded int to span
        private static int Write7BitEncodedIntToSpan(Span<byte> span, int value)
        {
            int written = 0;
            uint v = (uint)value;
            while (v >= 0x80)
            {
                span[written++] = (byte)(v | 0x80);
                v >>= 7;
            }
            span[written++] = (byte)v;
            return written;
        }








        //======  FIELDS  ======
        private byte[] _buffer;
        private bool _disposed;
        private int _length;
        private int _position;








        /// <summary>
        /// Initializes a new instance of <see cref="BufferStream"/> with the specified initial capacity.<br/>
        /// The default string encoding is <see cref="Encoding.UTF8"/>.
        /// </summary>
        /// <param name="initialCapacity">The initial size of the underlying buffer in bytes.</param>
        //======  CONSTRUCTORS  ======
        public BufferStream(int initialCapacity = 4096, Encoding? encoding = null)
        {
            if (encoding == null) encoding = Encoding.UTF8;
            if (initialCapacity <= 0)
                throw new ArgumentOutOfRangeException(nameof(initialCapacity), "Initial capacity must be positive.");

            _buffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
            _length = 0;
            _position = 0;
            _disposed = false;
            StringEncoding = encoding;
        }








        /// <summary>
        /// Gets the written contents as a read-only memory slice.
        /// </summary>
        //======  PROPERTIES  ======
        public ReadOnlyMemory<byte> AsReadOnlyMemory
        {
            get
            {
                EnsureNotDisposed();
                return _buffer.AsMemory(0, _length);
            }
        }

        /// <summary>
        /// Gets the written contents as a read-only span.
        /// </summary>
        public ReadOnlySpan<byte> AsReadOnlySpan
        {
            get
            {
                EnsureNotDisposed();
                return _buffer.AsSpan(0, _length);
            }
        }

        /// <summary>
        /// Returns a writable span of the written contents.
        /// </summary>
        public Span<byte> AsWritableSpan
        {
            get
            {
                EnsureNotDisposed();
                return _buffer.AsSpan(0, _length);
            }
        }

        /// <inheritdoc/>
        public override bool CanRead => !_disposed;

        /// <inheritdoc/>
        public override bool CanSeek => !_disposed;

        /// <inheritdoc/>
        public override bool CanWrite => !_disposed;

        /// <inheritdoc/>
        public override long Length => _length;

        /// <inheritdoc/>
        public override long Position
        {
            get
            {
                EnsureNotDisposed();
                return _position;
            }
            set
            {
                EnsureNotDisposed();
                if (value < 0 || value > _length)
                    throw new ArgumentOutOfRangeException(nameof(value), "Position must be within the length of the stream.");
                _position = (int)value;
            }
        }

        public Encoding StringEncoding { get; }








        /// <summary>
        /// Returns the underlying buffer to the shared pool and releases resources.
        /// </summary>
        /// <param name="disposing">True if called from Dispose; false if from finalizer.</param>
        //======  METHODS  ======
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = null!;
                _disposed = true;
            }
            base.Dispose(disposing);
        }








        /// <summary>
        /// Ensures the backing buffer can accommodate at least <paramref name="min"/> bytes.
        /// Rents a larger buffer if needed, copying existing data and returning the old buffer.
        /// </summary>
        /// <param name="min">The minimum required capacity.</param>
        private void EnsureCapacity(int min)
        {
            if (min <= _buffer.Length) return;
            int newSize = Math.Max(_buffer.Length * 2, min);
            var newBuf = ArrayPool<byte>.Shared.Rent(newSize);
            Array.Copy(_buffer, 0, newBuf, 0, _length);
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
            _buffer = newBuf;
        }

        /// <summary>
        /// Throws <see cref="ObjectDisposedException"/> if this stream has been disposed.
        /// </summary>
        private void EnsureNotDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(BufferStream));
        }

        private T ReadPrimitive<T>() where T : unmanaged
        {
            int size = Marshal.SizeOf<T>();
            if (_position + size > _length)
                throw new EndOfStreamException();

            T value = MemoryMarshal.Read<T>(_buffer.AsSpan(_position, size));
            _position += size;
            return value;
        }

        private void WriteAtOffset<T>(int destinationOffset, T value) where T : unmanaged
        {
            int size = Marshal.SizeOf<T>();
            if (destinationOffset < 0 || destinationOffset + size > _length)
                throw new ArgumentOutOfRangeException(nameof(destinationOffset), "Destination bounds must lie within written data.");

            MemoryMarshal.Write(_buffer.AsSpan(destinationOffset, size), ref value);
        }

        private void WritePrimitive<T>(T value) where T : unmanaged
        {
            int size = Unsafe.SizeOf<T>();
            EnsureCapacity(_position + size);
            MemoryMarshal.Write(_buffer.AsSpan(_position, size), ref value);
            _position += size;
            if (_position > _length)
                _length = _position;
        }








        /// <inheritdoc/>
        //------ Public Methods -----
        public override void Flush()
        {
            EnsureNotDisposed();
            // No-op since data is in-memory
        }

        /// <inheritdoc/>
        public override int Read(byte[] destination, int offset, int count)
        {
            var destSpan = destination.AsSpan(offset, count);
            var available = Math.Min(count, _length - _position);
            if (available <= 0) return 0;

            _buffer.AsSpan(_position, available).CopyTo(destSpan);
            _position += available;
            return available;
        }

        public int Read7BitEncodedInt()
        {
            int count = 0;
            int shift = 0;
            byte b;
            do
            {
                b = ReadByte();
                count |= (b & 0x7F) << shift;
                shift += 7;
            } while ((b & 0x80) != 0);
            return count;
        }

        /// <summary>
        /// Returns a segment of the buffer without changing the position.
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public byte[] ReadAtOffset(int offset, int count)
        {
            // Validate parameters
            if (offset < 0 || count < 0 || offset + count > _length)
                throw new ArgumentOutOfRangeException();

            // Get a read-only span of the desired slice
            var span = ReadOnlySpan(offset, count);

            // Copy to new array
            byte[] result = new byte[count];
            span.CopyTo(result);

            return result;
        }

        public T ReadLastOf<T>( ) where T : unmanaged
        {
            int size = Marshal.SizeOf<T>();
            if (_position + size > _length)
                throw new EndOfStreamException();
            return MemoryMarshal.Read<T>(_buffer.AsSpan(_length - size, size));
        }

        /// <summary>
        /// Copies bytes from this stream to another BufferStream
        /// </summary>
        /// <param name="destination">The destination BufferStream</param>
        /// <param name="count">Number of bytes to copy</param>
        public void CopyTo(BufferStream destination, int count)
        {
            EnsureNotDisposed();
            if (destination == null)
                throw new ArgumentNullException(nameof(destination));
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");

            // Ensure the destination has enough capacity
            destination.EnsureCapacity(destination._position + count);

            // Copy directly between the internal buffers
            _buffer.AsSpan(_position, count).CopyTo(destination._buffer.AsSpan(destination._position, count));

            // Update positions
            _position += count;
            destination._position += count;

            // Update destination length if needed
            if (destination._position > destination._length)
                destination._length = destination._position;
        }

        /// <summary>
        /// Copies all remaining bytes from this stream to another BufferStream
        /// </summary>
        /// <param name="destination">The destination BufferStream</param>
        public void CopyTo(BufferStream destination)
        {
            int remaining = _length - _position;
            CopyTo(destination, remaining);
        }
        public void CopyTo(byte[] destination, int offset, int count)
        {
            EnsureNotDisposed();
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");

            _buffer.AsSpan(_position, count).CopyTo(destination.AsSpan(offset, count));
            _position += count;
        }

        public void CopyTo(Memory<byte> destination)
        {
            EnsureNotDisposed();
            int available = _length - _position;
            if (available > destination.Length)
                available = destination.Length;

            _buffer.AsMemory(_position, available).CopyTo(destination);
            _position += available;
        }

        public void CopyTo(Memory<byte> destination, int count)
        {
            EnsureNotDisposed();
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");
            if (count > destination.Length)
                throw new ArgumentOutOfRangeException(nameof(count), "Destination too small");

            _buffer.AsMemory(_position, count).CopyTo(destination);
            _position += count;
        }

        public void CopyTo(Span<byte> destination)
        {
            EnsureNotDisposed();
            int available = _length - _position;
            if (available > destination.Length)
                available = destination.Length;

            _buffer.AsSpan(_position, available).CopyTo(destination);
            _position += available;
        }

        public void CopyTo(Span<byte> destination, int count)
        {
            EnsureNotDisposed();
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");
            if (count > destination.Length)
                throw new ArgumentOutOfRangeException(nameof(count), "Destination too small");

            _buffer.AsSpan(_position, count).CopyTo(destination);
            _position += count;
        }

        public void CopyTo(Stream destination, int count)
        {
            EnsureNotDisposed();
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");

            destination.Write(_buffer, _position, count);
            _position += count;
        }
        public byte ReadByte()
        {
            if (_position >= _length)
                throw new EndOfStreamException();
            return _buffer[_position++];
        }

        public byte[] ReadBytes(int count)
        {
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));

            int available = Math.Min(count, _length - _position);
            byte[] result = new byte[available];
            _buffer.AsSpan(_position, available).CopyTo(result);
            _position += available;
            return result;
        }

        public byte[] ReadBytesWithLength() => ReadArrayWithLength<byte>();

        public char ReadChar() => ReadPrimitive<char>();

        public DateOnly ReadDateOnly() => ReadPrimitive<DateOnly>();

        public DateTime ReadDateTime() => ReadPrimitive<DateTime>();

        public decimal ReadDecimal() => ReadPrimitive<decimal>();

        public double ReadDouble() => ReadPrimitive<double>();

        public Guid ReadGuid() => ReadPrimitive<Guid>();

        public short ReadInt16() => ReadPrimitive<short>();

        public int ReadInt32() => ReadPrimitive<int>();

        public long ReadInt64() => ReadPrimitive<long>();

        /// <summary>
        /// Returns a slice of the written contents.
        /// </summary>
        /// <param name="offset">The zero-based byte offset into the written buffer.</param>
        /// <param name="count">The number of bytes to include in the slice.</param>
        /// <returns>A <see cref="ReadOnlyMemory{T}"/> representing the requested slice.</returns>
        public ReadOnlyMemory<byte> ReadOnlyMemory(int offset, int count)
        {
            EnsureNotDisposed();
            if (offset < 0 || count < 0 || offset + count > _length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Slice bounds must lie within written data.");
            return _buffer.AsMemory(offset, count);
        }

        /// <summary>
        /// Returns a span of the written contents.
        /// </summary>
        /// <param name="offset">The zero-based byte offset into the written buffer.</param>
        /// <param name="count">The number of bytes to include in the span.</param>
        /// <returns>A <see cref="ReadOnlySpan{T}"/> representing the requested span.</returns>
        public ReadOnlySpan<byte> ReadOnlySpan(int offset, int count)
        {
            EnsureNotDisposed();
            if (offset < 0 || count < 0 || offset + count > _length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Slice bounds must lie within written data.");
            return _buffer.AsSpan(offset, count);
        }

        public float ReadSingle() => ReadPrimitive<float>();

        public string ReadString()
        {
            int length = Read7BitEncodedInt();
            var span = _buffer.AsSpan(_position, length);
            string value = StringEncoding.GetString(span);
            _position += length;
            return value;
        }

        public TimeOnly ReadTimeOnly()
        {
            long ticks = ReadInt64();
            return new TimeOnly(ticks);
        }

        public TimeSpan ReadTimeSpan()
        {
            long ticks = ReadInt64();
            return new TimeSpan(ticks);
        }

        public ushort ReadUInt16() => ReadPrimitive<ushort>();

        public uint ReadUInt32() => ReadPrimitive<uint>();

        public ulong ReadUInt64() => ReadPrimitive<ulong>();

        /// <summary>
        /// Resets the stream to an empty state. Optionally clears the buffer's contents.
        /// </summary>
        /// <param name="clearBuffer">
        /// If true, zeros out the written buffer contents up to the current length.
        /// </param>
        public void Reset(bool clearBuffer = false)
        {
            EnsureNotDisposed();

            if (clearBuffer && _length > 0)
                _buffer.AsSpan(0, _length).Clear();

            _position = 0;
            _length = 0;
        }

        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin)
        {
            EnsureNotDisposed();
            int newPos = origin switch
            {
                SeekOrigin.Begin => (int)offset,
                SeekOrigin.Current => _position + (int)offset,
                SeekOrigin.End => _length + (int)offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin), "Invalid SeekOrigin.")
            };
            if (newPos < 0 || newPos > _length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Seek position must be within the length of the stream.");
            _position = newPos;
            return _position;
        }

        /// <inheritdoc/>
        public override void SetLength(long value)
        {
            EnsureNotDisposed();
            if (value < 0 || value > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(value), "Length must be non-negative and within Int32 range.");

            EnsureCapacity((int)value);
            _length = (int)value;
            if (_position > _length)
                _position = _length;
        }

        public byte[] ToArray()
        {
            EnsureNotDisposed();
            return _buffer.AsSpan(0, _length).ToArray();
        }

        public void Write(bool value) => WritePrimitive(value);

        public void Write(byte value) => WritePrimitive(value);

        public void Write(short value) => WritePrimitive(value);

        public void Write(ushort value) => WritePrimitive(value);

        public void Write(int value) => WritePrimitive(value);

        public void Write(uint value) => WritePrimitive(value);

        public void Write(long value) => WritePrimitive(value);

        public void Write(ulong value) => WritePrimitive(value);

        public void Write(float value) => WritePrimitive(value);

        public void Write(double value) => WritePrimitive(value);

        public void Write(decimal value) => WritePrimitive(value);

        public void Write(char value) => WritePrimitive(value);

        public void Write(DateTime value) => WritePrimitive(value);

        public void Write(Guid value) => WritePrimitive(value);

        public void Write(DateOnly value)
        {
            Write(value.DayNumber);  // Int32
        }

        public void Write(TimeSpan value) => WritePrimitive(value);

        public void Write(TimeOnly value)
        {
            Write(value.Ticks);  // Int64
        }

        public void Write(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            var utf8Bytes = StringEncoding.GetBytes(value);
            Write7BitEncodedInt(utf8Bytes.Length);
            WriteBytes(utf8Bytes);
        }

        public override void Write(byte[] source, int offset, int count)
        {
            WriteBytes(source, offset, count);
        }

        public void Write7BitEncodedInt(int value)
        {
            uint v = (uint)value;
            while (v >= 0x80)
            {
                WriteByte((byte)(v | 0x80));
                v >>= 7;
            }
            WriteByte((byte)v);
        }

        public void Write7BitEncodedInt(uint value)
        {
            uint v = (uint)value;
            while (v >= 0x80)
            {
                WriteByte((byte)(v | 0x80));
                v >>= 7;
            }
            WriteByte((byte)v);
        }

        /// <summary>
        /// Returns a mutable span slice of the written contents.
        /// </summary>
        /// <param name="offset">The zero-based byte offset into the written buffer.</param>
        /// <param name="count">The number of bytes to include in the slice.</param>
        /// <returns>A <see cref="Span{T}"/> representing the requested slice.</returns>
        public Span<byte> WriteableSpan(int offset, int count)
        {
            EnsureNotDisposed();
            if (offset < 0 || count < 0 || offset + count > _length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Slice bounds must lie within written data.");
            return _buffer.AsSpan(offset, count);
        }

        public void WriteAtOffset(int destinationOffset, ReadOnlySpan<byte> source)
        {
            if (destinationOffset < 0 || destinationOffset + source.Length > _length)
                throw new ArgumentOutOfRangeException(nameof(destinationOffset), "Destination bounds must lie within written data.");

            source.CopyTo(_buffer.AsSpan(destinationOffset, source.Length));
        }

        public void WriteAtOffset(int destinationOffset, byte value) => WriteAtOffset<byte>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, sbyte value) => WriteAtOffset<sbyte>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, short value) => WriteAtOffset<short>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, ushort value) => WriteAtOffset<ushort>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, int value) => WriteAtOffset<int>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, uint value) => WriteAtOffset<uint>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, long value) => WriteAtOffset<long>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, ulong value) => WriteAtOffset<ulong>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, float value) => WriteAtOffset<float>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, double value) => WriteAtOffset<double>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, decimal value) => WriteAtOffset<decimal>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, bool value) => WriteAtOffset<bool>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, char value) => WriteAtOffset<char>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, Guid value) => WriteAtOffset<Guid>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, DateTime value) => WriteAtOffset<DateTime>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, TimeSpan value) => WriteAtOffset<TimeSpan>(destinationOffset, value);

        public void WriteAtOffset(int destinationOffset, string value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            byte[] bytes = StringEncoding.GetBytes(value);
            int totalSize = Get7BitEncodedIntSize(bytes.Length) + bytes.Length;

            if (destinationOffset < 0 || destinationOffset + totalSize > _length)
                throw new ArgumentOutOfRangeException(nameof(destinationOffset), "Destination bounds must lie within written data.");

            Span<byte> span = _buffer.AsSpan(destinationOffset, totalSize);

            // Write length as 7-bit encoded
            int written = Write7BitEncodedIntToSpan(span, bytes.Length);

            // Write string bytes
            bytes.AsSpan().CopyTo(span.Slice(written));
        }

        public void WriteAtOffset(int destinationOffset, byte[] source, int sourceOffset, int count)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            if (destinationOffset < 0 || destinationOffset + count > _length)
                throw new ArgumentOutOfRangeException(nameof(destinationOffset), "Destination bounds must lie within written data.");
            if (sourceOffset < 0 || count < 0 || sourceOffset + count > source.Length)
                throw new ArgumentOutOfRangeException(nameof(sourceOffset), "Source bounds are invalid.");

            source.AsSpan(sourceOffset, count).CopyTo(_buffer.AsSpan(destinationOffset, count));
        }

        public void WriteByte(byte value)
        {
            EnsureCapacity(_position + 1);
            _buffer[_position++] = value;
            if (_position > _length)
                _length = _position;
        }

        public void WriteBytes(ReadOnlySpan<byte> bytes)
        {
            EnsureCapacity(_position + bytes.Length);
            bytes.CopyTo(_buffer.AsSpan(_position));
            _position += bytes.Length;
            if (_position > _length)
                _length = _position;
        }

        public void WriteBytes(byte[] source, int offset, int count)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            if (offset < 0 || count < 0 || offset + count > source.Length)
                throw new ArgumentOutOfRangeException();

            EnsureCapacity(_position + count);
            source.AsSpan(offset, count).CopyTo(_buffer.AsSpan(_position));
            _position += count;
            if (_position > _length)
                _length = _position;
        }

        /// <summary>
        /// Writes a byte array with a 7bit encode length prefix.<br/>
        /// Read with <see cref="ReadBytesWithLength"/>
        /// </summary>
        /// <param name="source"></param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public void WriteBytesWithLength(byte[] source, int offset, int count)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            if (offset < 0 || count < 0 || offset + count > source.Length)
                throw new ArgumentOutOfRangeException();
            var lenSize = Get7BitEncodedIntSize(count);
            EnsureCapacity(_position + count + lenSize);
            Write7BitEncodedIntToSpan(_buffer.AsSpan(_position), count);
            _position += lenSize;
            source.AsSpan(offset, count).CopyTo(_buffer.AsSpan(_position));
            _position += count;
            if (_position > _length)
                _length = _position;
        }

        public void WriteSBytesWithLength(sbyte[] source) => WriteArrayWithLength(source);


        /// <summary>
        /// Writes a byte array with a 7bit encode length prefix.<br/>
        /// Read with <see cref="ReadBytesWithLength"/>
        /// </summary>
        /// <param name="source"></param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public void WriteBytesWithLength(byte[] source) => WriteArrayWithLength(source);

        public void WriteShortsWithLength(short[] source) => WriteArrayWithLength(source);

        public void WriteUShortsWithLength(ushort[] source) => WriteArrayWithLength(source);

        public void WriteIntsWithLength(int[] source) => WriteArrayWithLength(source);

        public void WriteUIntsWithLength(uint[] source) => WriteArrayWithLength(source);

        public void WriteLongsWithLength(long[] source) => WriteArrayWithLength(source);

        public void WriteULongsWithLength(ulong[] source) => WriteArrayWithLength(source);

        public void WriteFloatsWithLength(float[] source) => WriteArrayWithLength(source);

        public void WriteDoublesWithLength(double[] source) => WriteArrayWithLength(source);

        public void WriteGuidsWithLength(Guid[] source) => WriteArrayWithLength(source);

        public void WriteBooleansWithLength(bool[] source) => WriteArrayWithLength(source);

        public void WriteDateTimesWithLength(DateTime[] source) => WriteArrayWithLength(source);

        public void WriteTimespansWithLength(TimeSpan[] source) => WriteArrayWithLength(source);

        private void WriteArrayWithLength<T>(T[] source) where T : unmanaged
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            int byteCount = source.Length * Unsafe.SizeOf<T>();
            int lenSize = Get7BitEncodedIntSize(byteCount);
            EnsureCapacity(_position + byteCount + lenSize);

            // Write length prefix
            Write7BitEncodedIntToSpan(_buffer.AsSpan(_position), byteCount);
            _position += lenSize;

            // Write data as raw bytes
            var srcSpan = MemoryMarshal.AsBytes(source.AsSpan());
            srcSpan.CopyTo(_buffer.AsSpan(_position));
            _position += byteCount;

            if (_position > _length)
                _length = _position;
        }

        private T[] ReadArrayWithLength<T>() where T : unmanaged
        {
            int byteCount = Read7BitEncodedInt();
            if (byteCount < 0 || _position + byteCount > _length)
                throw new EndOfStreamException();

            int elementCount = byteCount / Unsafe.SizeOf<T>();
            T[] result = new T[elementCount];

            ReadOnlySpan<byte> src = _buffer.AsSpan(_position, byteCount);
            var destSpan = MemoryMarshal.AsBytes(result.AsSpan());
            src.CopyTo(destSpan);

            _position += byteCount;
            return result;
        }





    }
}
