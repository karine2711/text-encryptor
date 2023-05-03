package com.cybersec.encryptor.textencryptor.impl.caesar;

import com.cybersec.encryptor.textencryptor.exception.AlgorithmInstantiationException;

public class Caesar {
    public static final int LOWER_CASE_Z = 0x007A;
    public static final int LOWER_CASE_A = 0x0061;
    public static final int UPPER_CASE_Z = 0x005A;
    public static final int UPPER_CASE_A = 0x0041;
    private final int key;


    public Caesar(int key) {
        if (key >= 26) {
            throw new AlgorithmInstantiationException("The key is too large for Caesar!");
        }
        this.key = key;
    }

    public String encrypt(String text) {
        return applyCaesar(text, key);
    }

    public String decrypt(String text) {
        return applyCaesar(text, -key);
    }

    private String applyCaesar(String text, int key) {
        return text
            .codePoints()
            .map(cp -> Character.isUpperCase(cp) ? mapUpperCase(cp + key) : mapLowerCase(cp + key))
            .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
            .toString();
    }

    private int mapLowerCase(int i) {
        if (i > LOWER_CASE_Z) {
            return (i - LOWER_CASE_Z);
        } else if (i < LOWER_CASE_A) {
            return i + LOWER_CASE_A;
        }
        return i;
    }

    private int mapUpperCase(int i) {
        if (i > UPPER_CASE_Z) {
            return (i - UPPER_CASE_Z);
        } else if (i < UPPER_CASE_A) {
            return i + UPPER_CASE_A;
        }
        return i;
    }
}
