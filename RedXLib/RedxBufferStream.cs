using System;
using System.Buffers;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RedxLib
{
    /// <summary>
    /// Lightweight in-memory stream optimized for RedX workloads.
    /// </summary>
    public sealed class RedxBufferStream : Stream
    {
        private Memory<byte> _buffer;
        private byte[] _bufferBytes;
        private bool _disposed;
        private int _length;
        private int _position;
        private bool _resizable;

        /// <summary>
        /// Initializes a new instance of <see cref="RedxBufferStream"/> with the specified initial capacity.
        /// </summary>
        /// <param name="initialCapacity">The initial size of the underlying buffer in bytes.</param>
        public RedxBufferStream(int initialCapacity = 4096)
        {
            if (initialCapacity <= 0)
                throw new ArgumentOutOfRangeException(nameof(initialCapacity), "Initial capacity must be positive.");

            _bufferBytes = ArrayPool<byte>.Shared.Rent(initialCapacity);
            _buffer = _bufferBytes;
            _length = 0;
            _position = 0;
            _disposed = false;
            _resizable = true;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RedxBufferStream"/> over an existing buffer.
        /// </summary>
        /// <param name="existingBuffer">The backing buffer.</param>
        public RedxBufferStream(byte[] existingBuffer)
        {
            ArgumentNullException.ThrowIfNull(existingBuffer);

            _buffer = existingBuffer;
            _length = existingBuffer.Length;
            _position = 0;
            _disposed = false;
            _resizable = false;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="RedxBufferStream"/> over an existing memory buffer.
        /// </summary>
        /// <param name="existingBuffer">The backing memory buffer.</param>
        public RedxBufferStream(Memory<byte> existingBuffer)
        {
            _buffer = existingBuffer;
            _length = existingBuffer.Length;
            _position = 0;
            _disposed = false;
            _resizable = false;
        }

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

        /// <summary>
        /// Returns the underlying buffer to the shared pool and releases resources.
        /// </summary>
        /// <param name="disposing">True if called from Dispose; false if from finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (_bufferBytes != null)
                    ArrayPool<byte>.Shared.Return(_bufferBytes, clearArray: true);
                _buffer = default;
                _disposed = true;
            }
            base.Dispose(disposing);
        }

        /// <inheritdoc/>
        public override void Flush()
        {
            EnsureNotDisposed();
        }

        /// <inheritdoc/>
        public override int Read(byte[] destination, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(destination);
            if (offset < 0 || count < 0 || offset + count > destination.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));

            var destSpan = destination.AsSpan(offset, count);
            int available = Math.Min(count, _length - _position);
            if (available <= 0) return 0;

            _buffer.Span.Slice(_position, available).CopyTo(destSpan);
            _position += available;
            return available;
        }

        /// <summary>
        /// Reads the next byte from the buffer.
        /// </summary>
        /// <exception cref="EndOfStreamException">Thrown when no more data is available.</exception>
        public new byte ReadByte()
        {
            if (_position >= _length)
                throw new EndOfStreamException();
            return _buffer.Span[_position++];
        }

        /// <summary>
        /// Reads the specified number of bytes and advances the position.
        /// </summary>
        /// <param name="count">Maximum number of bytes to read.</param>
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

        /// <summary>
        /// Reads a 16-bit unsigned integer using the current endianness.
        /// </summary>
        public ushort ReadUInt16() => ReadPrimitive<ushort>();

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

        /// <summary>
        /// Materializes the written contents into a new array.
        /// </summary>
        public byte[] ToArray()
        {
            EnsureNotDisposed();
            return _buffer.Span.Slice(0, _length).ToArray();
        }

        /// <summary>
        /// Writes all bytes from another buffer stream into this instance.
        /// </summary>
        /// <param name="buffer">The source buffer stream.</param>
        public void Write(RedxBufferStream buffer)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            WriteBytes(buffer.AsReadOnlySpan);
        }

        /// <summary>
        /// Writes a single byte to the stream.
        /// </summary>
        public void Write(byte value) => WritePrimitive(value);

        /// <summary>
        /// Writes a 16-bit unsigned integer to the stream.
        /// </summary>
        public void Write(ushort value) => WritePrimitive(value);

        /// <summary>
        /// Writes a byte array to the stream.
        /// </summary>
        /// <param name="source">The data to write.</param>
        public void Write(byte[] source)
        {
            ArgumentNullException.ThrowIfNull(source);
            WriteBytes(source);
        }

        /// <inheritdoc/>
        public override void Write(byte[] source, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(source);
            if (offset < 0 || count < 0 || offset + count > source.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));

            WriteBytes(source.AsSpan(offset, count));
        }

        /// <summary>
        /// Writes a single byte to the stream.
        /// </summary>
        public void WriteByte(byte value)
        {
            EnsureCapacity(_position + 1);
            _buffer.Span[_position++] = value;
            if (_position > _length)
                _length = _position;
        }

        private void EnsureCapacity(int min)
        {
            if (min <= _buffer.Length) return;

            if (!_resizable)
                throw new InvalidOperationException("Buffer is fixed-size and cannot be resized.");

            int newSize = Math.Max(_buffer.Length * 2, min);
            var newBuf = ArrayPool<byte>.Shared.Rent(newSize);
            Array.Copy(_bufferBytes, 0, newBuf, 0, _length);
            ArrayPool<byte>.Shared.Return(_bufferBytes, clearArray: true);
            _bufferBytes = newBuf;
            _buffer = newBuf;
        }

        private void EnsureNotDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RedxBufferStream));
        }

        private T ReadPrimitive<T>() where T : unmanaged
        {
            int size = Unsafe.SizeOf<T>();
            if (_position + size > _length)
                throw new EndOfStreamException();

            T value = MemoryMarshal.Read<T>(_buffer.Span.Slice(_position, size));
            _position += size;
            return value;
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

        private void WriteBytes(ReadOnlySpan<byte> bytes)
        {
            EnsureCapacity(_position + bytes.Length);
            bytes.CopyTo(_buffer.Span.Slice(_position));
            _position += bytes.Length;
            if (_position > _length)
                _length = _position;
        }
    }
}
