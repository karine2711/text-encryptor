package com.cybersec.encryptor.textencryptor.impl.aes;

import com.cybersec.encryptor.textencryptor.impl.aes.Matrices.Sbox;
import java.util.Arrays;

public class KeyScheduler {
    private final byte[] key;
    private final byte[] part1;
    private final byte[] part2;
    private final byte[] part3;
    private final byte[] part4;
    private final byte[][] parts;
    private int constant = 1;

    KeyScheduler(byte[] key) {
        this.key = key;
        var quarterLength = this.key.length / 4;
        part1 = new byte[quarterLength];
        part2 = new byte[quarterLength];
        part3 = new byte[quarterLength];
        part4 = new byte[this.key.length - 3 * quarterLength];
        System.arraycopy(this.key, 0, part1, 0, quarterLength);
        System.arraycopy(this.key, quarterLength, part2, 0, quarterLength);
        System.arraycopy(this.key, 2 * quarterLength, part3, 0, quarterLength);
        System.arraycopy(this.key, 3 * quarterLength, part4, 0, this.key.length - 3 * quarterLength);
        parts = new byte[][] {part1, part2, part3, part4};
    }


    public byte[][] getNextKey() {
        for (int i = 0; i < parts.length; i++) {
            var part = Arrays.copyOf(parts[i], parts[i].length);
            rotWord(part);
            subPart(part);
            addConst(part);
            for (int j = 0; j < part.length; j++) {
                parts[i][j] = (byte) (parts[i][j] + part[j]);
            }
        }
        System.arraycopy(part1, 0, key, 0, part1.length);
        System.arraycopy(part2, 0, key, part1.length, part2.length);

        System.arraycopy(part3, 0, key, 2 * part1.length, part3.length);
        System.arraycopy(part4, 0, key, 3 * part1.length, part4.length);
        return Matrices.constructStateMatrix(key);
    }

    private void addConst(byte[] part) {
        part[0] = (byte) (part[0] + constant);
        if (constant < 0x80) {
            constant = (2 * constant);
        } else {
            constant = ((2 * constant) ^ 0x11B);
        }
    }

    private void subPart(byte[] word) {
        var tmp = Arrays.copyOf(word, word.length);
        for (int i = 0; i < word.length; i++) {
            word[i] = Sbox.getSubstitute(tmp[i]);
        }
    }

    private void rotWord(byte[] word) {
        shiftLeft(word);
    }


    private byte[] shiftLeft(byte[] arr) {
        byte temp = arr[0];
        System.arraycopy(arr, 1, arr, 0, arr.length - 1);
        arr[arr.length - 1] = temp;
        return arr;
    }

}
