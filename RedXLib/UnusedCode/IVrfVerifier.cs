using System;

namespace RedxLib
{
    /// <summary>
    /// VRF verifier interface. Implementations live at system-level and are
    /// supplied to VerifyAuthority to validate proofs.
    /// </summary>
    public interface IVrfVerifier
    {
        bool Verify(ReadOnlySpan<byte> vrfPublicKey, ReadOnlySpan<byte> transcriptTi, ReadOnlySpan<byte> proofBlob);
    }
}
