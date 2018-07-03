using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Extensions.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Extensions.Crypto.Signers
{
    public class Gost34310x94Signer : Gost3410Signer
    {
        private Gost34310KeyParameters key;
        private SecureRandom random;

        public override string AlgorithmName
        {
            get { return "GOST34310"; }
        }

        public override void Init(
            bool forSigning,
            ICipherParameters parameters)
        {
            if (forSigning)
            {
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

                if (!(parameters is Gost34310PrivateKeyParameters))
                    throw new InvalidKeyException("GOST34310 private key required for signing");

                throw new NotImplementedException();
                //this.key = (Gost34310PrivateKeyParameters)parameters;
            }
            else
            {
                if (!(parameters is Gost34310x94PublicKeyParameters))
                    throw new InvalidKeyException("GOST34310 public key required for signing");

                this.key = (Gost34310x94PublicKeyParameters)parameters;
            }
        }

        /**
		 * generate a signature for the given message using the key we were
		 * initialised with. For conventional Gost3410 the message should be a Gost3411
		 * hash of the message of interest.
		 *
		 * @param message the message that will be verified later.
		 */
        public override BigInteger[] GenerateSignature(
            byte[] message)
        {
            throw new NotImplementedException();
        }

        /**
		 * return true if the value r and s represent a Gost3410 signature for
		 * the passed in message for standard Gost3410 the message should be a
		 * Gost3411 hash of the real message to be verified.
		 */
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

            BigInteger m = new BigInteger(1, mRev);
            Gost3410Parameters parameters = key.Parameters;

            if (r.SignValue < 0 || parameters.Q.CompareTo(r) <= 0)
            {
                return false;
            }

            if (s.SignValue < 0 || parameters.Q.CompareTo(s) <= 0)
            {
                return false;
            }

            BigInteger v = m.ModPow(parameters.Q.Subtract(BigInteger.Two), parameters.Q);

            BigInteger z1 = s.Multiply(v).Mod(parameters.Q);
            BigInteger z2 = (parameters.Q.Subtract(r)).Multiply(v).Mod(parameters.Q);

            z1 = parameters.A.ModPow(z1, parameters.P);
            z2 = ((Gost34310x94PublicKeyParameters)key).Y.ModPow(z2, parameters.P);

            BigInteger u = z1.Multiply(z2).Mod(parameters.P).Mod(parameters.Q);

            return u.Equals(r);
        }
    }
}
