using System;

namespace RobinsonEncryptionLib
{
    public interface IChameleonHash
    {
        /// <summary>
        /// Public parameters (shared in ROK).
        /// </summary>
        byte[] PublicParam { get; }

        /// <summary>
        /// Compute the chameleon hash H = CH(x, r).
        /// </summary>
        /// <param name="index">The index or value to hide.</param>
        /// <param name="nonce">The per‐index random nonce.</param>
        /// <returns>A fixed‐size hash output.</returns>
        byte[] Compute(int index, byte nonce);

        /// <summary>
        /// Invert H given the nonce, returning the original index.
        /// Requires knowledge of the secret trapdoor.
        /// </summary>
        /// <param name="H">The hash output.</param>
        /// <param name="nonce">The nonce used at Compute time.</param>
        /// <returns>The original index.</returns>
        int Invert(byte[] H, byte nonce);
    }
}
