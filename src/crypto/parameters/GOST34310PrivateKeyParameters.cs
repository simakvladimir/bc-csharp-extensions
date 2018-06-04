using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Extensions.Crypto.Parameters
{
    public class Gost34310PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        public Gost34310PrivateKeyParameters(
            bool isPrivate)
            : base(isPrivate)
        {
        }
    }
}
