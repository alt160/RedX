using System;
using System.Buffers;
using System.Runtime.InteropServices;
using Blake3;

namespace RobinsonEncryptionLib
{
    public sealed class Blake3XofReader : IDisposable
    {
        private readonly Hasher _hasher;
        private readonly byte[] _buffer;
        private int _bufferOffset;
        private int _bufferCount;
        private ulong _streamOffset;
        private readonly int _blockSize;

        /// <summary>
        /// Create a BLAKE3 XOF stream from the given 3 input sources.<br/>
        /// Inputs are added to the hasher in the order of the inputs.
        /// </summary>
        /// <param name="input">Input to hash (e.g., key, iv, etc).</param>
        /// <param name="blockSize">Internal buffer size. Default is 4096.</param>
        public Blake3XofReader(ReadOnlySpan<byte> input1, ReadOnlySpan<byte> input2, ReadOnlySpan<byte> input3, int blockSize = 4096)
        {
            if (blockSize <= 0) blockSize = 4096;
            _blockSize = blockSize;
            _buffer = ArrayPool<byte>.Shared.Rent(_blockSize);
            _hasher = Hasher.New();
            _hasher.Update(input1);
            _hasher.Update(input2);
            _hasher.Update(input3);
            _bufferOffset = 0;
            _bufferCount = 0;
            _streamOffset = 0;
        }

        /// <summary>
        /// Create a BLAKE3 XOF stream from the given 2 input sources.<br/>
        /// Inputs are added to the hasher in the order of the inputs.
        /// </summary>
        /// <param name="input">Input to hash (e.g., key, iv, etc).</param>
        /// <param name="blockSize">Internal buffer size. Default is 4096.</param>
        public Blake3XofReader(ReadOnlySpan<byte> input1, ReadOnlySpan<byte> input2, int blockSize = 4096, string? tag = null)
        {
            if (blockSize <= 0) blockSize = 4096;
            _blockSize = blockSize;
            _buffer = ArrayPool<byte>.Shared.Rent(_blockSize);
            if (tag != null) _hasher = Hasher.NewKeyed(;

            _hasher = Hasher.New();
            _hasher.Update(input1);
            _hasher.Update(input2);
            _bufferOffset = 0;
            _bufferCount = 0;
            _streamOffset = 0;
        }

        /// <summary>
        /// Create a BLAKE3 XOF stream from the given input source.
        /// </summary>
        /// <param name="input">Input to hash (e.g., key, iv, etc).</param>
        /// <param name="blockSize">Internal buffer size. Default is 4096.</param>
        public Blake3XofReader(ReadOnlySpan<byte> input, int blockSize = 4096)
        {
            if (blockSize <= 0) blockSize = 4096;
            _blockSize = blockSize;
            _buffer = ArrayPool<byte>.Shared.Rent(_blockSize);
            _hasher = Hasher.New();
            _hasher.Update(input);
            _bufferOffset = 0;
            _bufferCount = 0;
            _streamOffset = 0;
        }

        /// <summary>
        /// Fills the given span with pseudo-random data from the Blake3 XOF stream.
        /// </summary>
        public void ReadNext(Span<byte> output)
        {
            int written = 0;

            while (written < output.Length)
            {
                if (_bufferOffset >= _bufferCount)
                {
                    // refill internal buffer
                    _hasher.Finalize(_streamOffset, _buffer.AsSpan(0, _blockSize));
                    _bufferOffset = 0;
                    _bufferCount = _blockSize;
                    _streamOffset += (ulong)_blockSize;
                }

                int remaining = output.Length - written;
                int available = _bufferCount - _bufferOffset;
                int toCopy = Math.Min(remaining, available);

                _buffer.AsSpan(_bufferOffset, toCopy).CopyTo(output.Slice(written, toCopy));
                written += toCopy;
                _bufferOffset += toCopy;
            }
        }

        public T ReadNextOf<T>() where T : unmanaged
        {
            var bytes = new byte[Marshal.SizeOf<T>()];
            ReadNext(bytes);
            return MemoryMarshal.Cast<byte, T>(bytes)[0];
        }
        public void ReadNextOfInto<T>(ref T output) where T : unmanaged
        {
            var bytes = new byte[Marshal.SizeOf<T>()];
            ReadNext(bytes);
            output = MemoryMarshal.Cast<byte, T>(bytes)[0];
        }


        public void ReadNext(Span<ushort> output)
        {
            // Convert Span<short> to Span<byte> (little-endian representation)
            var byteSpan = MemoryMarshal.AsBytes(output);
            ReadNext(byteSpan);
        }

        public void ReadNext(Span<uint> output)
        {
            // Convert Span<short> to Span<byte> (little-endian representation)
            var byteSpan = MemoryMarshal.AsBytes(output);
            ReadNext(byteSpan);
        }

        public void ReadNext(Span<short> output)
        {
            // Convert Span<short> to Span<byte> (little-endian representation)
            var byteSpan = MemoryMarshal.AsBytes(output);
            ReadNext(byteSpan);
        }

        public void ReadNext(Span<int> output)
        {
            // Convert Span<short> to Span<byte> (little-endian representation)
            var byteSpan = MemoryMarshal.AsBytes(output);
            ReadNext(byteSpan);
        }

        public void ReadNext(Span<Guid> output)
        {
            // Convert Span<short> to Span<byte> (little-endian representation)
            var byteSpan = MemoryMarshal.AsBytes(output);
            ReadNext(byteSpan);
        }

        public void Dispose()
        {
            _hasher.Dispose();
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
        }
    }
}
