using System;
using System.Buffers;
using System.Runtime.InteropServices;
using Blake3;

namespace RedxLib
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

    public sealed class JumpGenerator : IDisposable
    {
        private readonly Blake3XofReader[] _readers;
        private readonly int _streams;

        /// <summary>
        /// Builds a jump generator from an arbitrarily‐long master secret.
        /// </summary>
        /// <param name="masterSecret">High-entropy keying material (e.g. 64, 128 bytes…)</param>
        /// <param name="streams">
        ///   Number of independent 256-bit seeds to derive.  
        ///   1 ⇒ 256-bit security; 2 ⇒ 512-bit; 3 ⇒ 768-bit; etc.
        /// </param>
        /// <param name="context">Per-message nonce/IV to absorb into each stream.</param>
        public JumpGenerator(ReadOnlySpan<byte> masterSecret, int streams, ReadOnlySpan<byte> context = default)
        {
            if (streams < 1)
                throw new ArgumentOutOfRangeException(nameof(streams));

            _streams = streams;

            // 1) Extract step: XOF(masterSecret) ⇒ streams*32 bytes
            //    Use stackalloc for up to, say, 8 streams (8*32=256B on stack)
            Span<byte> extOut = stackalloc byte[streams * 32];
            var extractor = Blake3.Hasher.New();
            extractor.Update(masterSecret);
            extractor.Finalize(extOut);   // fills extOut with an XOF of length extOut.Length

            // 2) Split extOut into N sub-seeds and build one XofReader each
            _readers = new Blake3XofReader[streams];
            for (int i = 0; i < streams; i++)
            {
                // grab the i-th 32-byte seed
                ReadOnlySpan<byte> seed32 = extOut.Slice(i * 32, 32);
                if (context.IsEmpty)
                    _readers[i] = new Blake3XofReader(seed32);
                else
                    _readers[i] = new Blake3XofReader(seed32, context);
            }
        }

        /// <summary>
        /// Returns the next 32-bit skip value by XOR-combining one UInt32 from each stream.
        /// </summary>
        public uint NextJump32()
        {
            // stackalloc a 4-byte scratch buffer for all streams
            Span<byte> scratch = stackalloc byte[4];
            uint combined = 0;

            for (int i = 0; i < _streams; i++)
            {
                _readers[i].ReadNext(scratch);                            // you’ll implement Read(Span<byte>) in Blake3XofReader
                combined ^= MemoryMarshal.Read<uint>(scratch);
            }

            return combined;
        }

        /// <summary>
        /// Returns the next 16-bit skip value by XOR-combining one UInt16 from each stream.
        /// </summary>
        public ushort NextJump16()
        {
            // stackalloc a 2-byte scratch buffer for all streams
            Span<byte> scratch = stackalloc byte[2];
            ushort combined = 0;

            for (int i = 0; i < _streams; i++)
            {
                _readers[i].ReadNext(scratch);                            // you’ll implement Read(Span<byte>) in Blake3XofReader
                combined ^= MemoryMarshal.Read<ushort>(scratch);
            }

            return combined;
        }


        public void Dispose()
        {
            foreach (var r in _readers) r.Dispose();
        }
    }


}
