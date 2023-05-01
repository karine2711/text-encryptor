package com.cybersec.encryptor.textencryptor.impl.ECC;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import com.cybersec.encryptor.textencryptor.impl.ECC.EncryptorEllipticCurve.Point;

public class EllipticCurveEncryptor {
    private final static int PADDING = 0xFF;
    private final EncryptorEllipticCurve curve;

    public EllipticCurveEncryptor(EncryptorEllipticCurve curve) {
        this.curve = curve;
    }

    // generates public and private keys using the elliptic curve and returns as string
    public KeySet generateKeySet() {
        final var curveKeySet = curve.generateKeySet();
        return KeySet.fromEllipticCurveKeySet(curveKeySet);
    }

    // encrypts using the elliptic curve and public key
    public String encrypt(String message, String publicKey) {
        final var messagePoint = messageToPoint(message);
        final var publicKeyPoint = Point.fromString(publicKey);
        return curve.encrypt(messagePoint, publicKeyPoint).toString();
    }

    // decrypts using the elliptic curve and private key
    public String decrypt(String cipher, String privateKey) {
        final var privateKeyBigInt = new BigInteger(privateKey);
        return getStringFromPoint(curve.decrypt(EncryptorEllipticCurve.Cipher.fromString(cipher), privateKeyBigInt));
    }

    // Maps a certain point on the elliptic curve to the given message by getting the bytes of the message
    // and trying to express it as an x coordinate of the point. Repeats with different sizes of overhead
    // until an x value is found that is valid ( has a corresponding y value )
    private Point messageToPoint(String message) {
        byte[] messageBytes = message.getBytes();
        BigInteger x;
        Point result;
        int padding = 0;

        do {
            // Add padding to the message bytes
            byte[] paddedBytes = new byte[messageBytes.length + 4 + padding];
            System.arraycopy(messageBytes, 0, paddedBytes, 0, messageBytes.length);
            paddedBytes[messageBytes.length + padding] = (byte) ((padding >> 24) & PADDING);
            paddedBytes[messageBytes.length + padding + 1] = (byte) ((padding >> 16) & PADDING);
            paddedBytes[messageBytes.length + padding + 2] = (byte) ((padding >> 8) & PADDING);
            paddedBytes[messageBytes.length + padding + 3] = (byte) (padding & PADDING);

            // Convert the padded bytes to a BigInteger
            BigInteger messageBigInt = new BigInteger(1, paddedBytes);

            // Use the BigInteger as x coordinate
            x = messageBigInt.mod(curve.getPrime());

            // Get the corresponding y coordinate
            result = Point.createPointFromX(x, curve);

            // Increment padding if no y coordinate found
            padding++;
        } while (result.yValue() == null);

        return result;
    }

    // reverse of the previous method
    private String getStringFromPoint(Point point) {
        BigInteger x = point.xValue();

        byte[] bytes = x.toByteArray();
        int paddingLength = 0;
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == (byte) PADDING) {
                paddingLength = bytes.length - i - 1;
                break;
            }
        }
        byte[] messageBytes = new byte[bytes.length - paddingLength];
        System.arraycopy(bytes, paddingLength, messageBytes, 0, messageBytes.length);
        return new String(messageBytes, StandardCharsets.UTF_8);
    }


    public record KeySet(
            String publicKey,
            String privateKey
    ){
        private static KeySet fromEllipticCurveKeySet(EncryptorEllipticCurve.KeySet curveKeySet) {
            return new KeySet(curveKeySet.publicKey().toString(), curveKeySet.privateKey().toString());
        }
    }

    // Used this method for encrypting and decrypting a string value by obtaining a point on the elliptic curve from message and vice versa
    //https://andrea.corbellini.name/2023/01/02/ec-encryption/
}