using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Extensions.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Extensions.Crypto.Signers
{
    /**
     * GOST KZ 34.310-2004
     */
    public class Gost34310x2004Signer : ECGost3410Signer
    {
        private Gost34310X2004PublicKeyParameters key;
        private SecureRandom random;

        public override string AlgorithmName
        {
            get { return "ECGOST3410"; }
        }

        public override void Init(
            bool forSigning,
            ICipherParameters parameters)
        {
            if (forSigning)
            {
                /*
                if (parameters is ParametersWithRandom)
                {
                    ParametersWithRandom rParam = (ParametersWithRandom)parameters;

                    this.random = rParam.Random;
                    parameters = rParam.Parameters;
                }
                else
                {
                    this.random = new SecureRandom();
                }

                if (!(parameters is ECPrivateKeyParameters))
                    throw new InvalidKeyException("EC private key required for signing");

                this.key = (ECPrivateKeyParameters)parameters;
                */
            }
            else
            {
                if (!(parameters is Gost34310X2004PublicKeyParameters))
                    throw new InvalidKeyException("EC public key required for verification");

                this.key = (Gost34310X2004PublicKeyParameters)parameters;
            }
        }

        public override bool VerifySignature(
            byte[] message,
            BigInteger r,
            BigInteger s)
        {
            byte[] mRev = new byte[message.Length]; // conversion is little-endian
            for (int i = 0; i != mRev.Length; i++)
            {
                mRev[i] = message[mRev.Length - 1 - i];
            }

            BigInteger e = new BigInteger(1, mRev);
            BigInteger n = key.Parameters.N;

            // r in the range [1,n-1]
            if (r.CompareTo(BigInteger.One) < 0 || r.CompareTo(n) >= 0)
            {
                return false;
            }

            // s in the range [1,n-1]
            if (s.CompareTo(BigInteger.One) < 0 || s.CompareTo(n) >= 0)
            {
                return false;
            }

            BigInteger v = e.ModInverse(n);

            BigInteger z1 = s.Multiply(v).Mod(n);
            BigInteger z2 = (n.Subtract(r)).Multiply(v).Mod(n);

            ECPoint G = key.Parameters.G; // P
            ECPoint Q = ((Gost34310X2004PublicKeyParameters)key).Q;

            ECPoint point = ECAlgorithms.SumOfTwoMultiplies(G, z1, Q, z2).Normalize();

            if (point.IsInfinity)
                return false;

            BigInteger R = point.AffineXCoord.ToBigInteger().Mod(n);

            return R.Equals(r);
        }
    }
}
