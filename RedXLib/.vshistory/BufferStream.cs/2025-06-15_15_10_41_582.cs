using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;








namespace RobinsonEncryptionLib
{
    //====== TYPES ======
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
        private byte[] _bufferBytes;
        private Memory<byte> _buffer;
        private bool _disposed;
        private int _length;
        private int _position;
        private bool _resizable = false;







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

            _bufferBytes = ArrayPool<byte>.Shared.Rent(initialCapacity);
            _buffer = _bufferBytes;
            _length = 0;
            _position = 0;
            _disposed = false;
            _resizable = true;
            StringEncoding = encoding;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="BufferStream"/> with the specified existing buffer.<br/>
        /// The default string encoding is <see cref="Encoding.UTF8"/>
        /// This contstructor makes BufferStream fixed-sized due to the pre-existing buffer provided.
        /// </summary>
        /// <param name="existingBuffer"></param>
        /// <param name="encoding"></param>
        public BufferStream(byte[] existingBuffer, Encoding? encoding = null)
        {
            if (encoding == null) encoding = Encoding.UTF8;
            _buffer = existingBuffer;
            _length = existingBuffer.Length;
            _position = 0;
            _disposed = false;
            _resizable = false;
            StringEncoding = encoding;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="BufferStream"/> with the specified existing buffer.<br/>
        /// The default string encoding is <see cref="Encoding.UTF8"/>
        /// This contstructor makes BufferStream fixed-sized due to the pre-existing buffer provided.
        /// </summary>
        /// <param name="existingBuffer"></param>
        /// <param name="encoding"></param>
        public BufferStream(Memory<byte> existingBuffer, Encoding? encoding = null)
        {
            if (encoding == null) encoding = Encoding.UTF8;
            _buffer = existingBuffer;
            _length = existingBuffer.Length;
            _position = 0;
            _disposed = false;
            _resizable = false;
            StringEncoding = encoding;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="BufferStream"/> with the specified existing buffer.<br/>
        /// The default string encoding is <see cref="Encoding.UTF8"/>
        /// This contstructor makes BufferStream fixed-sized due to the pre-existing buffer provided.
        /// </summary>
        /// <param name="existingBuffer"></param>
        /// <param name="encoding"></param>
        public BufferStream(Span<byte> existingBuffer, Encoding? encoding = null)
        {
            if (encoding == null) encoding = Encoding.UTF8;
            _buffer = existingBuffer.ToArray();
            _length = existingBuffer.Length;
            _position = 0;
            _disposed = false;
            _resizable = false;
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
                return _buffer.Slice(0, _length);
            }
        }

        public Span<byte> SliceAtCurrent(int length) => _buffer.Span.Slice(_position, length);
        public ReadOnlySpan<byte> ReadonlySliceAtCurrent(int length) => _buffer.Span.Slice(_position, length);

        public BufferStream SegmentAtCurrent(int length) => new BufferStream(_buffer.Slice(_position, length));
        public BufferStream SegmentAtCurrent() => new BufferStream(_buffer.Slice(_position,  _length - _position));

        /// <summary>
        /// Gets the written contents as a read-only span.
        /// </summary>
        public ReadOnlySpan<byte> AsReadOnlySpan
        {
            get
            {
                EnsureNotDisposed();
                return _buffer.Span.Slice(0, _length);
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
                return _buffer.Span.Slice(0, _length);
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
                // only rented buffers will fill _bufferBytes
                if (_bufferBytes != null)
                    ArrayPool<byte>.Shared.Return(_bufferBytes, clearArray: true);
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

            if (!_resizable)
                throw new InvalidOperationException("Buffer is fixed-size or overlayed and cannot be resized.");

            int newSize = Math.Max(_buffer.Length * 2, min);
            var newBuf = ArrayPool<byte>.Shared.Rent(newSize);
            Array.Copy(_bufferBytes, 0, newBuf, 0, _length);
            ArrayPool<byte>.Shared.Return(_bufferBytes, clearArray: true);
            _bufferBytes = newBuf;
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

        private T[] ReadArrayWithLength<T>() where T : unmanaged
        {
            int byteCount = Read7BitEncodedInt();
            if (byteCount < 0 || _position + byteCount > _length)
                throw new EndOfStreamException();

            int elementCount = byteCount / Unsafe.SizeOf<T>();
            T[] result = new T[elementCount];

            ReadOnlySpan<byte> src = _buffer.Span.Slice(_position, byteCount);
            var destSpan = MemoryMarshal.AsBytes(result.AsSpan());
            src.CopyTo(destSpan);

            _position += byteCount;
            return result;
        }

        private T ReadPrimitive<T>() where T : unmanaged
        {
            int size = Marshal.SizeOf<T>();
            if (_position + size > _length)
                throw new EndOfStreamException();

            T value = MemoryMarshal.Read<T>(_buffer.Span.Slice(_position, size));
            _position += size;
            return value;
        }

        private void WriteArrayWithLength<T>(T[] source) where T : unmanaged
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            int byteCount = source.Length * Unsafe.SizeOf<T>();
            int lenSize = Get7BitEncodedIntSize(byteCount);
            EnsureCapacity(_position + byteCount + lenSize);

            // Write length prefix
            Write7BitEncodedIntToSpan(_buffer.Span.Slice(_position), byteCount);
            _position += lenSize;

            // Write data as raw bytes
            var srcSpan = MemoryMarshal.AsBytes(source.AsSpan());
            srcSpan.CopyTo(_buffer.Span.Slice(_position));
            _position += byteCount;

            if (_position > _length)
                _length = _position;
        }

        private void WriteAtOffset<T>(int destinationOffset, T value) where T : unmanaged
        {
            int size = Marshal.SizeOf<T>();
            if (destinationOffset < 0 || destinationOffset + size > _length)
                throw new ArgumentOutOfRangeException(nameof(destinationOffset), "Destination bounds must lie within written data.");

            MemoryMarshal.Write(_buffer.Span.Slice(destinationOffset, size), ref value);
        }

        private void WritePrimitive<T>(T value) where T : unmanaged
        {
            int size = Unsafe.SizeOf<T>();
            EnsureCapacity(_position + size);
            MemoryMarshal.Write(_buffer.Span.Slice(_position, size), ref value);
            _position += size;
            if (_position > _length)
                _length = _position;
        }








        /// <summary>
        /// Copies all remaining bytes from this stream to another BufferStream
        /// </summary>
        /// <param name="destination">The destination BufferStream</param>
        //------ Public Methods -----
        public void CopyTo(BufferStream destination)
        {
            var pos = _position;
            _position = 0;
            try
            {
                CopyTo(destination, _length);
            }
            finally
            {
                _position = pos;
            }
        }

        public void CopyTo(Memory<byte> destination)
        {
            EnsureNotDisposed();
            int available = _length - _position;
            if (available > destination.Length)
                available = destination.Length;

            _buffer.Slice(_position, available).CopyTo(destination);
            _position += available;
        }

        public void CopyTo(Span<byte> destination)
        {
            EnsureNotDisposed();
            int available = _length - _position;
            if (available > destination.Length)
                available = destination.Length;

            _buffer.Span.Slice(_position, available).CopyTo(destination);
            _position += available;
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
            _buffer.Span.Slice(_position, count).CopyTo(destination.SliceAtCurrent(count));

            // Update positions
            _position += count;
            destination._position += count;

            // Update destination length if needed
            if (destination._position > destination._length)
                destination._length = destination._position;
        }

        public void CopyTo(Memory<byte> destination, int count)
        {
            EnsureNotDisposed();
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");
            if (count > destination.Length)
                throw new ArgumentOutOfRangeException(nameof(count), "Destination too small");

            _buffer.Slice(_position, count).CopyTo(destination);
            _position += count;
        }

        public void CopyTo(Span<byte> destination, int count)
        {
            EnsureNotDisposed();
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");
            if (count > destination.Length)
                throw new ArgumentOutOfRangeException(nameof(count), "Destination too small");

            _buffer.Span.Slice(_position, count).CopyTo(destination);
            _position += count;
        }

        public void CopyTo(Stream destination, int count)
        {
            EnsureNotDisposed();
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");

            // Use the Span directly without converting to an array
            Span<byte> bufferSpan = _buffer.Span.Slice(_position, count);
            // You can use the MemoryMarshal.AsBytes method if you need a byte[] representation
            byte[] bufferArray = MemoryMarshal.AsBytes(bufferSpan).ToArray();

            // Write the bufferArray to the destination stream, starting at 0 since the array is freshly allocated
            destination.Write(bufferArray, 0, count);
            _position += count;
        }
        public void CopyTo(byte[] destination, int offset, int count)
        {
            EnsureNotDisposed();
            if (count > _length - _position)
                throw new ArgumentOutOfRangeException(nameof(count), "Not enough bytes available");

            _buffer.Span.Slice(_position, count).CopyTo(destination.AsSpan(offset, count));
            _position += count;
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

            _buffer.Span.Slice(_position, available).CopyTo(destSpan);
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

        public new byte ReadByte()
        {
            if (_position >= _length)
                throw new EndOfStreamException();
            return _buffer.Span[_position++];
        }

        public byte[] ReadBytes(int count)
        {
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));

            int available = Math.Min(count, _length - _position);
            byte[] result = new byte[available];
            _buffer.Span.Slice(_position, available).CopyTo(result);
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

        public T ReadLastOf<T>() where T : unmanaged
        {
            int size = Marshal.SizeOf<T>();
            if (_length < size)
                throw new EndOfStreamException("Not enough data to read the requested type.");
            return MemoryMarshal.Read<T>(_buffer.Span.Slice(_length - size, size));
        }

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
            return _buffer.Slice(offset, count);
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
            return _buffer.Span.Slice(offset, count);
        }

        public float ReadSingle() => ReadPrimitive<float>();

        public string ReadString()
        {
            int length = Read7BitEncodedInt();
            var span = _buffer.Span.Slice(_position, length);
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
                _buffer.Span.Slice(0, _length).Clear();

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
            return _buffer.Span.Slice(0, _length).ToArray();
        }

        public void Write(BufferStream buffer) => buffer.CopyTo(this);
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
            uint v = value;
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
            return _buffer.Span.Slice(offset, count);
        }

        public void WriteAtOffset(int destinationOffset, ReadOnlySpan<byte> source)
        {
            if (destinationOffset < 0 || destinationOffset + source.Length > _length)
                throw new ArgumentOutOfRangeException(nameof(destinationOffset), "Destination bounds must lie within written data.");

            source.CopyTo(_buffer.Span.Slice(destinationOffset, source.Length));
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

            Span<byte> span = _buffer.Span.Slice(destinationOffset, totalSize);

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

            source.AsSpan(sourceOffset, count).CopyTo(_buffer.Span.Slice(destinationOffset, count));
        }

        public void WriteBooleansWithLength(bool[] source) => WriteArrayWithLength(source);

        public void WriteByte(byte value)
        {
            EnsureCapacity(_position + 1);
            _buffer.Span[_position++] = value;
            if (_position > _length)
                _length = _position;
        }

        public void WriteBytes(ReadOnlySpan<byte> bytes)
        {
            EnsureCapacity(_position + bytes.Length);
            bytes.CopyTo(_buffer.Span.Slice(_position));
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
            source.AsSpan(offset, count).CopyTo(_buffer.Span.Slice(_position));
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
        public void WriteBytesWithLength(byte[] source) => WriteArrayWithLength(source);

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
            Write7BitEncodedIntToSpan(_buffer.Span.Slice(_position), count);
            _position += lenSize;
            source.AsSpan(offset, count).CopyTo(_buffer.Span.Slice(_position));
            _position += count;
            if (_position > _length)
                _length = _position;
        }

        public void WriteDateTimesWithLength(DateTime[] source) => WriteArrayWithLength(source);

        public void WriteDoublesWithLength(double[] source) => WriteArrayWithLength(source);

        public void WriteFloatsWithLength(float[] source) => WriteArrayWithLength(source);

        public void WriteGuidsWithLength(Guid[] source) => WriteArrayWithLength(source);

        public void WriteIntsWithLength(int[] source) => WriteArrayWithLength(source);

        public void WriteLongsWithLength(long[] source) => WriteArrayWithLength(source);

        public void WriteSBytesWithLength(sbyte[] source) => WriteArrayWithLength(source);

        public void WriteShortsWithLength(short[] source) => WriteArrayWithLength(source);

        public void WriteTimespansWithLength(TimeSpan[] source) => WriteArrayWithLength(source);

        public void WriteUIntsWithLength(uint[] source) => WriteArrayWithLength(source);

        public void WriteULongsWithLength(ulong[] source) => WriteArrayWithLength(source);

        public void WriteUShortsWithLength(ushort[] source) => WriteArrayWithLength(source);








    }
}
