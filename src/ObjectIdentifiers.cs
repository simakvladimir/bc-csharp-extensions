using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Extensions
{
    public class ObjectIdentifiers
    {
        public static readonly DerObjectIdentifier GostR34310Key = new DerObjectIdentifier("1.2.398.3.10.1.1.1.1");
        public static readonly DerObjectIdentifier GostR34311Digest = new DerObjectIdentifier("1.2.398.3.10.1.3.1");
        public static readonly DerObjectIdentifier GostR34310Encryption = new DerObjectIdentifier("1.2.398.3.10.1.1.1.2"); // encryption alg
    }
}
