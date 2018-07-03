using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;

namespace Org.BouncyCastle.Extensions.Asn1
{
    public class Gost34310PublicKeyAlgParameters : Gost3410PublicKeyAlgParameters
    {
        public Gost34310PublicKeyAlgParameters(DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet) 
            : base(publicKeyParamSet, digestParamSet)
        {
        }

        public Gost34310PublicKeyAlgParameters(DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet, DerObjectIdentifier encryptionParamSet) 
            : base(publicKeyParamSet, digestParamSet, encryptionParamSet)
        {
        }

        public Gost34310PublicKeyAlgParameters(Asn1Sequence seq) 
            : base(seq)
        {
        }
    }
}
