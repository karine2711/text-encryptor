package com.cybersec.encryptor.textencryptor.impl.util;

import java.math.BigInteger;

public class Constants {

    public static final BigInteger NUMS_P_384_PRIME = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec3", 16);
    public static final BigInteger NUMS_P_384_A_COEFF = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec0", 16);
    public static final BigInteger NUMS_P_384_B_COEFF = new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff77bb", 16);
    public static final BigInteger NUMS_P_384_GEN_X = new BigInteger("02", 16);
    public static final BigInteger NUMS_P_384_GEN_Y = new BigInteger("3c9f82cb4b87b4dc71e763e0663e5dbd8034ed422f04f82673330dc58d15ffa2b4a3d0bad5d30f865bcbbf503ea66f43", 16);
    public static final BigInteger NUMS_P_384_ORDER = new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffd61eaf1eeb5d6881beda9d3d4c37e27a604d81f67b0e61b9", 16);

    public static final BigInteger NIST_P_384_PRIME = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);
    public static final BigInteger NIST_P_384_A_COEFF = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16);
    public static final BigInteger NIST_P_384_B_COEFF = new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16);
    public static final BigInteger NIST_P_384_GEN_X = new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16);
    public static final BigInteger NIST_P_384_GEN_Y = new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16);
    public static final BigInteger NIST_P_384_ORDER = new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16);

    public static final BigInteger NIST_P_521_PRIME = new BigInteger("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
    public static final BigInteger NIST_P_521_A_COEFF = new BigInteger("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16);
    public static final BigInteger NIST_P_521_B_COEFF = new BigInteger("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16);
    public static final BigInteger NIST_P_521_GEN_X = new BigInteger("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16);
    public static final BigInteger NIST_P_521_GEN_Y = new BigInteger("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16);
    public static final BigInteger NIST_P_521_ORDER = new BigInteger("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16);


    //source https://neuromancer.sk/std/
}
