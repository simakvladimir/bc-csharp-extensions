using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Extensions.Asn1
{
    public sealed class Gost34310NamedParameters
    {
        private Gost34310NamedParameters()
        {
        }

        private static readonly IDictionary objIds = Platform.CreateHashtable();
        private static readonly IDictionary parameters = Platform.CreateHashtable();

        private static readonly Gost34310ParamSetParameters kncaA = new Gost34310ParamSetParameters(
            1024,
            new BigInteger("139454871199115825601409655107690713107041707059928031797758001454375765357722984094124368522288239833039114681648076688236921220737322672160740747771700911134550432053804647694904686120113087816240740184800477047157336662926249423571248823968542221753660143391485680840520336859458494803187341288580489525163"),
            new BigInteger("79885141663410976897627118935756323747307951916507639758300472692338873533959"),
            new BigInteger("42941826148615804143873447737955502392672345968607143066798112994089471231420027060385216699563848719957657284814898909770759462613437669456364882730370838934791080835932647976778601915343474400961034231316672578686920482194932878633360203384797092684342247621055760235016132614780652761028509445403338652341")
            //            validationAlgorithm {
            //                    algorithm
            //                        id-GostR3410-94-bBis,
            //                    parameters
            //                        GostR3410-94-ValidationBisParameters: {
            //                            x0      1376285941,
            //                            c       3996757427
            //                        }
            //                }

        );

        static Gost34310NamedParameters()
        {
            parameters[ObjectIdentifiers.GostR34310x95A] = kncaA;

            objIds["Gost34310-95-A"] = ObjectIdentifiers.GostR34310x95A;
        }

        public static Gost34310ParamSetParameters GetByOid(
            DerObjectIdentifier oid)
        {
            return (Gost34310ParamSetParameters)parameters[oid];
        }

        public static IEnumerable Names
        {
            get { return new EnumerableProxy(objIds.Keys); }
        }

        public static Gost34310ParamSetParameters GetByName(
            string name)
        {
            DerObjectIdentifier oid = (DerObjectIdentifier)objIds[name];

            if (oid != null)
            {
                return (Gost34310ParamSetParameters)parameters[oid];
            }

            return null;
        }

        public static DerObjectIdentifier GetOid(
            string name)
        {
            return (DerObjectIdentifier)objIds[name];
        }
    }
}
