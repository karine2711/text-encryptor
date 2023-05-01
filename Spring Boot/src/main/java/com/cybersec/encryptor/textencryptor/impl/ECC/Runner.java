package com.cybersec.encryptor.textencryptor.impl.ECC;

public class Runner {
    public static void main(String[] args) {

        final var encryptor = new EllipticCurveEncryptor(EncryptorEllipticCurve.NUMS_P_384);
//        final var encryptor = new EllipticCurveEncryptor(EncryptorEllipticCurve.NIST_P_384);
//        final var encryptor = new EllipticCurveEncryptor(EncryptorEllipticCurve.NIST_P_521);

        final var message = "Davit and Karine will get a 100";
        System.out.println("Message: " + message);

        final var keySet = encryptor.generateKeySet();
        System.out.println("Public Key: " + keySet.publicKey());
        System.out.println("Private Key:" + keySet.privateKey());
        System.out.println();

        final var cipher = encryptor.encrypt(message, keySet.publicKey());

        System.out.println("Ciphered message");
        System.out.println(cipher);
        System.out.println();

        final var deciphered = encryptor.decrypt(cipher, keySet.privateKey());
        System.out.println("Deciphered Message: " + deciphered);
    }
}
