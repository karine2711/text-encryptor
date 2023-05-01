package com.cybersec.encryptor.textencryptor.impl.aes;

import static com.cybersec.encryptor.textencryptor.impl.aes.Matrices.constructStateMatrix;

import com.cybersec.encryptor.textencryptor.impl.aes.Matrices.ColumnMix;
import com.cybersec.encryptor.textencryptor.impl.aes.Matrices.Sbox;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class AES128 {
    AESChunkEncryptor chunkEncryptor;
    List<byte[][]> keys = new ArrayList<>();

    public AES128(byte[] masterKey) {
        this.chunkEncryptor = new AESChunkEncryptor(keys);
        KeyScheduler scheduler = new KeyScheduler(masterKey);
        keys.add(constructStateMatrix(masterKey));
        for (int i = 0; i < 10; i++) {
            keys.add(scheduler.getNextKey());
        }
    }

    public synchronized String encrypt(String text) {
        List<byte[][]> states = chunkString(text.getBytes(StandardCharsets.UTF_8))
            .stream()
            .map(Matrices::constructStateMatrix)
            .collect(Collectors.toList());
        List<byte[]> encrypted = new ArrayList<>();
        states.forEach(s -> encrypted.add(chunkEncryptor.encrypt(s)));
        byte[] result = new byte[encrypted.size() * 16];
        int offset = 0;
        for (byte[] bytes : encrypted) {
            System.arraycopy(bytes, 0, result, offset, bytes.length);
            offset += bytes.length;
        }
        return Base64.getEncoder().encodeToString(result);
    }

    public synchronized String decrypt(String cypertext) {
        List<byte[][]> states = chunkString(Base64.getDecoder().decode(cypertext))
            .stream()
            .map(Matrices::constructStateMatrix).collect(Collectors.toList());
        List<byte[]> decrypted = new ArrayList<>();
        states.forEach(s -> decrypted.add(chunkEncryptor.decrypt(s)));
        byte[] result = new byte[decrypted.size() * 16];
        int offset = 0;
        for (byte[] bytes : decrypted) {
            System.arraycopy(bytes, 0, result, offset, bytes.length);
            offset += bytes.length;
        }
        result = getWithoutPadding(result);
        return new String(result, StandardCharsets.UTF_8);
    }

    private byte[] getWithoutPadding(byte[] result) {
        var i = result.length - 1;
        var lastByte = result[i];
        i--;
        while (result[i] == lastByte) {
            i--;
        }
        byte[] unPadded = new byte[i + 1];
         System.arraycopy(result, 0, unPadded, 0, i + 1);
         return unPadded;
    }

    public static List<byte[]> chunkString(byte[] byteArray) {
        List<byte[]> chunks = new ArrayList<>();
        for (int i = 0; i < byteArray.length; i += 16) {
            byte[] chunk = Arrays.copyOfRange(byteArray, i, i + 16);
            if (byteArray.length - i < 16) {
                byte[] paddedChunk = new byte[16];
                Arrays.fill(paddedChunk, (byte) (16 - byteArray.length + i));
                System.arraycopy(chunk, 0, paddedChunk, 0, byteArray.length - i);
                chunk = paddedChunk;
            }
            chunks.add(chunk);
        }
        return chunks;
    }
}

class AESChunkEncryptor {
    List<byte[][]> keys = new ArrayList<>();

    public AESChunkEncryptor(List<byte[][]> keys) {
        this.keys = keys;
    }

    public byte[] encrypt(byte[][] textChunk) {
        doEncryptRound(textChunk, 0, 0);
        int rows = textChunk.length;
        int cols = textChunk[0].length;
        byte[] vector = new byte[rows * cols];
        int k = 0;
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                vector[k++] = textChunk[i][j];
            }
        }
        return vector;
    }


    public byte[] decrypt(byte[][] cyperChunk) {
        doDecryptRound(cyperChunk, keys.size() - 1, 0);
        return getFlat(cyperChunk);
    }

    public void doEncryptRound(byte[][] state, int keyIndex, int round) {
        if (round == 11) {
            return;
        }
        if (round == 0) {
            xorWithKey(state, keys.get(keyIndex));
            doEncryptRound(state, keyIndex + 1, round + 1);
            return;
        }
        var key = keys.get(keyIndex);
        Sbox.inplaceSubstitute(state);
        shiftRowsLeft(state);
        if (round != 10) {
            ColumnMix.mix(state);
        }
        xorWithKey(state, key);
        doEncryptRound(state, keyIndex + 1, round + 1);
    }

    public void doDecryptRound(byte[][] state, int keyIndex, int round) {
        if (round == 11) {
            return;
        }
        if (round == 0) {
            xorWithKey(state, keys.get(keyIndex));
            doDecryptRound(state, keyIndex - 1, round + 1);
            return;
        }
        var key = keys.get(keyIndex);
        if (round != 1) {
            ColumnMix.inverseMix(state);
        }
        shiftRowsRight(state);
        Sbox.inplaceInverseSubstitute(state);
        xorWithKey(state, key);
        doDecryptRound(state, keyIndex - 1, round + 1);
    }

    private void shiftRowsLeft(byte[][] stateMatrix) {
        for (int i = 0; i < stateMatrix.length; i++) {
            circularLeftShift(stateMatrix[i], i);
        }
    }

    private void shiftRowsRight(byte[][] stateMatrix) {
        for (int i = 0; i < stateMatrix.length; i++) {
            circularRightShift(stateMatrix[i], i);
        }
    }

    public static void circularLeftShift(byte[] arr, int shift) {
        int n = arr.length;
        byte[] shifted = new byte[n];
        System.arraycopy(arr, shift, shifted, 0, n - shift);
        System.arraycopy(arr, 0, shifted, n - shift, shift);

        System.arraycopy(shifted, 0, arr, 0, n);
    }

    public static void circularRightShift(byte[] arr, int shift) {
        int n = arr.length;
        byte[] shifted = new byte[n];
        System.arraycopy(arr, 0, shifted, shift, n - shift);
        System.arraycopy(arr, n - shift, shifted, 0, shift);

        System.arraycopy(shifted, 0, arr, 0, n);
    }

    private void xorWithKey(byte[][] state, byte[][] key) {
        for (int i = 0; i < state.length; i++) {
            for (int j = 0; j < state[i].length; j++) {
                state[i][j] = (byte) (state[i][j] ^ key[i][j]);
            }
        }
    }

    public byte[] getFlat(byte[][] matrix) {
        int rows = matrix.length;
        int cols = matrix[0].length;
        byte[] vector = new byte[rows * cols];
        int k = 0;
        for (byte[] bytes : matrix) {
            for (byte b : bytes) {
                vector[k++] = b;
            }
        }
        return vector;
    }
}
