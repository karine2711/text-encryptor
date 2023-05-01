package com.cybersec.encryptor.textencryptor.impl.ECC;

import java.math.BigInteger;
import java.security.SecureRandom;

import static com.cybersec.encryptor.textencryptor.impl.util.Constants.*;

public final class EncryptorEllipticCurve {
    // Popular Elliptic Curve Equations
    static EncryptorEllipticCurve NUMS_P_384 = new EncryptorEllipticCurve(
            NUMS_P_384_A_COEFF,
            NUMS_P_384_B_COEFF,
            NUMS_P_384_PRIME,
            NUMS_P_384_ORDER,
            new Point(NUMS_P_384_GEN_X, NUMS_P_384_GEN_Y)
    );

    static EncryptorEllipticCurve NIST_P_384 = new EncryptorEllipticCurve(
            NIST_P_384_A_COEFF,
            NIST_P_384_B_COEFF,
            NIST_P_384_PRIME,
            NIST_P_384_ORDER,
            new Point(NIST_P_384_GEN_X, NIST_P_384_GEN_Y)
    );

    static EncryptorEllipticCurve NIST_P_521 = new EncryptorEllipticCurve(
            NIST_P_521_A_COEFF,
            NIST_P_521_B_COEFF,
            NIST_P_521_PRIME,
            NIST_P_521_ORDER,
            new Point(NIST_P_521_GEN_X, NIST_P_521_GEN_Y)
    );

    private final BigInteger coeffA;
    private final BigInteger coeffB;
    private final BigInteger prime;
    private final BigInteger order;
    private final Point generator;

    private EncryptorEllipticCurve(BigInteger coeffA, BigInteger coeffB, BigInteger prime, BigInteger order, Point generator) {
        this.coeffA = coeffA;
        this.coeffB = coeffB;
        this.prime = prime;
        this.order = order;
        this.generator = generator;
    }

    // Generates a keyset, where private key is a random number smaller than the order of the elliptic curve
    // and public key is a point on the curve obtained by multiplying the private key by the generator point
    public KeySet generateKeySet() {
        final var privateKey = generatePrivateKey();
        final var publicKey = generator.multiplyByScalar(privateKey, this);
        return new KeySet(publicKey, privateKey);
    }

    // Encrypts the given message point using the public key
    public Cipher encrypt(Point message, Point publicKey) {
        final var blindingFactor = generateBlindingFactor();
        final var c1 = generator.multiplyByScalar(blindingFactor, this);
        final var c2 = message.addPointOrDouble(publicKey.multiplyByScalar(blindingFactor, this), this);
        return new Cipher(c1, c2);
    }

    // Decrypts the given cipher uing the private key
    public Point decrypt(Cipher cipher, BigInteger privateKey) {
        return cipher.c2.subtractPoint(cipher.c1.multiplyByScalar(privateKey, this), this);
    }

    private BigInteger generatePrivateKey() {
        final var random = new SecureRandom();
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(order.bitLength(), random);
        } while (privateKey.compareTo(BigInteger.ZERO) <= 0 || privateKey.compareTo(order) >= 0);
        return privateKey;
    }

    private BigInteger generateBlindingFactor() {
        final var random = new SecureRandom();
        BigInteger blindingFactor;
        do {
            blindingFactor = new BigInteger(order.bitLength(), random);
        } while (blindingFactor.compareTo(order) >= 0);
        return blindingFactor;
    }

    public BigInteger getPrime() {
        return prime;
    }

    // A class representing a point on the elliptic curve, which has elliptic curve algebraic function implementations
    // such as point addition, subtraction, doubling and multiplication by scalar
    public record Point(
            BigInteger xValue,
            BigInteger yValue
    ) {

        public static Point fromString(String str) {
            final var coordinates = str.split(",");
            final var x = new BigInteger(coordinates[0]);
            final var y = new BigInteger(coordinates[1]);
            return new Point(x, y);
        }

        // a method that creates a point on the elliptic curve given the x coordinate by trying to find a suitable y coordinate
        public static Point createPointFromX(BigInteger x, EncryptorEllipticCurve curve) {
            // Calculate the right-hand side of the equation y^2 = x^3 + ax + b
            final var rhs = x.pow(3).add(curve.coeffA.multiply(x)).add(curve.coeffB);

            // Calculate the left-hand side of the equation y^2 = x^3 + ax + b
            // using the Tonelli-Shanks algorithm
            final var prime = curve.prime;
            final var y = sqrt(rhs, prime);

            return new Point(x, y);
        }

        // The following two methods are an implementation of something called the Tonelli-Shanks algorithm which is needed
        // for getting the y coordinate
        private static BigInteger sqrt(BigInteger n, BigInteger p) {
            if (n.modPow(p.subtract(BigInteger.ONE).divide(new BigInteger("2")), p).compareTo(BigInteger.ONE) != 0) {
                return BigInteger.ZERO;
            }
            if (p.mod(new BigInteger("4")).compareTo(new BigInteger("3")) == 0) {
                return n.modPow(p.add(BigInteger.ONE).divide(new BigInteger("4")), p);
            }
            BigInteger s = p.subtract(BigInteger.ONE);
            BigInteger e = BigInteger.ZERO;
            while (s.mod(new BigInteger("2")).equals(BigInteger.ZERO)) {
                s = s.divide(new BigInteger("2"));
                e = e.add(BigInteger.ONE);
            }
            BigInteger n1 = BigInteger.ONE;
            while (jacobiSymbol(n1, p) != -1) {
                n1 = n1.add(BigInteger.ONE);
            }
            BigInteger x = n.modPow(s.add(BigInteger.ONE).divide(new BigInteger("2")), p);
            BigInteger b = n.modPow(s, p);
            BigInteger g = n1.modPow(s, p);
            BigInteger r = e;
            while (true) {
                BigInteger t = b;
                int m = 0;
                for (m = 0; m < r.intValue(); m++) {
                    if (t.equals(BigInteger.ONE)) {
                        break;
                    }
                    t = t.modPow(new BigInteger("2"), p);
                }
                if (m == 0) {
                    return x;
                }
                BigInteger gs = g.modPow(new BigInteger("2").pow(r.intValue() - m - 1), p);
                g = gs.modPow(new BigInteger("2"), p);
                x = x.multiply(gs).mod(p);
                b = b.multiply(g).mod(p);
                r = new BigInteger(Integer.toString(m));
            }
        }

        private static int jacobiSymbol(BigInteger a, BigInteger n) {
            if (n.compareTo(BigInteger.ONE) <= 0 || n.mod(BigInteger.TWO).equals(BigInteger.ZERO))
                throw new IllegalArgumentException("Jacobi symbol is defined only for odd n > 1");

            int result = 1;
            if (a.compareTo(BigInteger.ZERO) < 0) {
                a = a.negate();
                if (n.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)))
                    result = -result;
            }

            if (a.equals(BigInteger.ZERO))
                return 0;

            BigInteger temp = a;
            int e = 0;
            while (temp.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
                e++;
                temp = temp.divide(BigInteger.TWO);
            }

            if (e % 2 == 1 && (n.mod(BigInteger.valueOf(8)).equals(BigInteger.valueOf(3))
                    || n.mod(BigInteger.valueOf(8)).equals(BigInteger.valueOf(5))))
                result = -result;

            if (n.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))
                    && temp.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)))
                result = -result;

            if (temp.equals(BigInteger.ONE))
                return result;
            else
                return result * jacobiSymbol(n.mod(temp), temp);
        }

        // elliptic curve algebra - adding two points or double if the same
        public Point addPointOrDouble(Point other, EncryptorEllipticCurve curve) {
            if (other == null) {
                return this;
            }

            if (equals(other)) {
                return doubleSelf(curve);
            } else {
                return addPoint(other, curve);
            }
        }

        // elliptic curve algebra - subtracting two points
        public Point subtractPoint(Point other, EncryptorEllipticCurve curve) {
            final var negatedOther = new Point(other.xValue, other.yValue.negate());
            return addPointOrDouble(negatedOther, curve);
        }

        // elliptic curve algebra - doubling a point
        public Point doubleSelf(EncryptorEllipticCurve curve) {
            final var prime = curve.prime;
            final var slope = xValue.multiply(xValue).multiply(BigInteger.valueOf(3)).add(curve.coeffA).multiply(yValue.multiply(BigInteger.valueOf(2)).modInverse(prime));
            final var x3 = slope.multiply(slope).subtract(xValue.multiply(BigInteger.valueOf(2))).mod(prime);
            final var y3 = slope.multiply(xValue.subtract(x3)).subtract(yValue).mod(prime);
            return new Point(x3, y3);
        }

        // elliptic curve algebra - adding two points
        public Point addPoint(Point other, EncryptorEllipticCurve curve) {
            final var x2 = other.xValue;
            final var y2 = other.yValue;
            final var prime = curve.prime;
            final var slope = yValue.subtract(y2).multiply(xValue.subtract(x2).modInverse(prime));
            final var x3 = slope.multiply(slope).subtract(xValue).subtract(x2).mod(prime);
            final var y3 = slope.multiply(xValue.subtract(x3)).subtract(yValue).mod(prime);
            return new Point(x3, y3);
        }

        // elliptic curve algebra - multiplying point by scalar
        public Point multiplyByScalar(BigInteger k, EncryptorEllipticCurve curve) {
            if (k.equals(BigInteger.ZERO)) {
                return null;
            }
            if (k.equals(BigInteger.ONE)) {
                return this;
            }
            Point q = multiplyByScalar(k.divide(BigInteger.valueOf(2)), curve);
            q = q.doubleSelf(curve);

            if (k.mod(BigInteger.valueOf(2)).equals(BigInteger.ONE)) {
                q = q.addPointOrDouble(this, curve);
            }
            return q;
        }


        @Override
        public boolean equals(Object obj) {
            final var otherPoint = (Point) obj;
            return this.xValue.equals(otherPoint.xValue) && this.yValue.equals(otherPoint.yValue);
        }

        @Override
        public String toString() {
            return xValue + "," + yValue;
        }
    }

    public record KeySet(
            Point publicKey,
            BigInteger privateKey
    ) {

    }

    public record Cipher(
            Point c1,
            Point c2
    ) {
        public static Cipher fromString(String str){
            final var points = str.split("&");
            return new Cipher(Point.fromString(points[0]), Point.fromString(points[1]));
        }

        @Override
        public String toString() {
            return c1.toString() + "&" + c2.toString();
        }
    }
}



