using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Extensions.Crypto.Digests
{
    public class Gost34311Digest : IDigest, IMemoable
    {
        private Gost3411Digest digest = new Gost3411Digest(Gost28147Engine.GetSBox("D-Test"));

        public string AlgorithmName
        {
            get { return "Gost34311"; }
        }

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            digest.BlockUpdate(input, inOff, length);
        }

        public IMemoable Copy()
        {
            return digest.Copy();
        }

        public int DoFinal(byte[] output, int outOff)
        {
            return digest.DoFinal(output, outOff);
        }

        public int GetByteLength()
        {
            return digest.GetByteLength();
        }

        public int GetDigestSize()
        {
            return digest.GetDigestSize();
        }

        public void Reset()
        {
            digest.Reset();
        }

        public void Reset(IMemoable other)
        {
            digest.Reset(other);
        }

        public void Update(byte input)
        {
            digest.Update(input);
        }
    }
}
