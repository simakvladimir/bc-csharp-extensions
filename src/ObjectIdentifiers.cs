using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Extensions
{
    public class ObjectIdentifiers
    {
        public static readonly DerObjectIdentifier GostR34310x2004Key = new DerObjectIdentifier("1.2.398.3.10.1.1.1.1");
        public static readonly DerObjectIdentifier GostR34310x94Key = new DerObjectIdentifier("1.2.398.3.6.3.1.2.1"); // NOTE: should revalidate
        public static readonly DerObjectIdentifier GostR34311Digest = new DerObjectIdentifier("1.2.398.3.10.1.3.1");
        public static readonly DerObjectIdentifier GostR34310x94Encryption = new DerObjectIdentifier("1.2.398.3.6.3.1.2.2"); // encryption alg // NOTE: recheck
        public static readonly DerObjectIdentifier GostR34310x2004Encryption = new DerObjectIdentifier("1.2.398.3.10.1.1.1.2");

        public static readonly DerObjectIdentifier GostR34310x95A = new DerObjectIdentifier("1.2.398.3.10.1.1.1.1.1");
        public static readonly DerObjectIdentifier GostR34310x2004A = new DerObjectIdentifier("1.2.398.3.10.1.1.1.1.1");

    }
}
