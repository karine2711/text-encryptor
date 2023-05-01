package com.cybersec.encryptor.textencryptor.impl.aes;

import java.util.Arrays;

public class Matrices {
    public static class Sbox {
        private static final short[] SBOX = {
            (short) 0x63, (short) 0x7c, (short) 0x77, (short) 0x7b, (short) 0xf2, (short) 0x6b, (short) 0x6f, (short) 0xc5,
            (short) 0x30, (short) 0x01, (short) 0x67, (short) 0x2b, (short) 0xfe, (short) 0xd7, (short) 0xab, (short) 0x76,
            (short) 0xca, (short) 0x82, (short) 0xc9, (short) 0x7d, (short) 0xfa, (short) 0x59, (short) 0x47, (short) 0xf0,
            (short) 0xad, (short) 0xd4, (short) 0xa2, (short) 0xaf, (short) 0x9c, (short) 0xa4, (short) 0x72, (short) 0xc0,
            (short) 0xb7, (short) 0xfd, (short) 0x93, (short) 0x26, (short) 0x36, (short) 0x3f, (short) 0xf7, (short) 0xcc,
            (short) 0x34, (short) 0xa5, (short) 0xe5, (short) 0xf1, (short) 0x71, (short) 0xd8, (short) 0x31, (short) 0x15,
            (short) 0x04, (short) 0xc7, (short) 0x23, (short) 0xc3, (short) 0x18, (short) 0x96, (short) 0x05, (short) 0x9a,
            (short) 0x07, (short) 0x12, (short) 0x80, (short) 0xe2, (short) 0xeb, (short) 0x27, (short) 0xb2, (short) 0x75,
            (short) 0x09, (short) 0x83, (short) 0x2c, (short) 0x1a, (short) 0x1b, (short) 0x6e, (short) 0x5a, (short) 0xa0,
            (short) 0x52, (short) 0x3b, (short) 0xd6, (short) 0xb3, (short) 0x29, (short) 0xe3, (short) 0x2f, (short) 0x84,
            (short) 0x53, (short) 0xd1, (short) 0x00, (short) 0xed, (short) 0x20, (short) 0xfc, (short) 0xb1, (short) 0x5b,
            (short) 0x6a, (short) 0xcb, (short) 0xbe, (short) 0x39, (short) 0x4a, (short) 0x4c, (short) 0x58, (short) 0xcf,
            (short) 0xd0, (short) 0xef, (short) 0xaa, (short) 0xfb, (short) 0x43, (short) 0x4d, (short) 0x33, (short) 0x85,
            (short) 0x45, (short) 0xf9, (short) 0x02, (short) 0x7f, (short) 0x50, (short) 0x3c, (short) 0x9f, (short) 0xa8,
            (short) 0x51, (short) 0xa3, (short) 0x40, (short) 0x8f, (short) 0x92, (short) 0x9d, (short) 0x38, (short) 0xf5,
            (short) 0xbc, (short) 0xb6, (short) 0xda, (short) 0x21, (short) 0x10, (short) 0xff, (short) 0xf3, (short) 0xd2,
            (short) 0xcd, (short) 0x0c, (short) 0x13, (short) 0xec, (short) 0x5f, (short) 0x97, (short) 0x44, (short) 0x17,
            (short) 0xc4, (short) 0xa7, (short) 0x7e, (short) 0x3d, (short) 0x64, (short) 0x5d, (short) 0x19, (short) 0x73,
            (short) 0x60, (short) 0x81, (short) 0x4f, (short) 0xdc, (short) 0x22, (short) 0x2a, (short) 0x90, (short) 0x88,
            (short) 0x46, (short) 0xee, (short) 0xb8, (short) 0x14, (short) 0xde, (short) 0x5e, (short) 0x0b, (short) 0xdb,
            (short) 0xe0, (short) 0x32, (short) 0x3a, (short) 0x0a, (short) 0x49, (short) 0x06, (short) 0x24, (short) 0x5c,
            (short) 0xc2, (short) 0xd3, (short) 0xac, (short) 0x62, (short) 0x91, (short) 0x95, (short) 0xe4, (short) 0x79,
            (short) 0xe7, (short) 0xc8, (short) 0x37, (short) 0x6d, (short) 0x8d, (short) 0xd5, (short) 0x4e, (short) 0xa9,
            (short) 0x6c, (short) 0x56, (short) 0xf4, (short) 0xea, (short) 0x65, (short) 0x7a, (short) 0xae, (short) 0x08,
            (short) 0xba, (short) 0x78, (short) 0x25, (short) 0x2e, (short) 0x1c, (short) 0xa6, (short) 0xb4, (short) 0xc6,
            (short) 0xe8, (short) 0xdd, (short) 0x74, (short) 0x1f, (short) 0x4b, (short) 0xbd, (short) 0x8b, (short) 0x8a,
            (short) 0x70, (short) 0x3e, (short) 0xb5, (short) 0x66, (short) 0x48, (short) 0x03, (short) 0xf6, (short) 0x0e,
            (short) 0x61, (short) 0x35, (short) 0x57, (short) 0xb9, (short) 0x86, (short) 0xc1, (short) 0x1d, (short) 0x9e,
            (short) 0xe1, (short) 0xf8, (short) 0x98, (short) 0x11, (short) 0x69, (short) 0xd9, (short) 0x8e, (short) 0x94,
            (short) 0x9b, (short) 0x1e, (short) 0x87, (short) 0xe9, (short) 0xce, (short) 0x55, (short) 0x28, (short) 0xdf,
            (short) 0x8c, (short) 0xa1, (short) 0x89, (short) 0x0d, (short) 0xbf, (short) 0xe6, (short) 0x42, (short) 0x68,
            (short) 0x41, (short) 0x99, (short) 0x2d, (short) 0x0f, (short) 0xb0, (short) 0x54, (short) 0xbb, (short) 0x16
        };
        private static final short[] INVERSE_SBOX = {
            (short) 0x52, (short) 0x09, (short) 0x6A, (short) 0xD5, (short) 0x30, (short) 0x36, (short) 0xA5, (short) 0x38,
            (short) 0xBF, (short) 0x40, (short) 0xA3, (short) 0x9E, (short) 0x81, (short) 0xF3, (short) 0xD7, (short) 0xFB,
            (short) 0x7C, (short) 0xE3, (short) 0x39, (short) 0x82, (short) 0x9B, (short) 0x2F, (short) 0xFF, (short) 0x87,
            (short) 0x34, (short) 0x8E, (short) 0x43, (short) 0x44, (short) 0xC4, (short) 0xDE, (short) 0xE9, (short) 0xCB,
            (short) 0x54, (short) 0x7B, (short) 0x94, (short) 0x32, (short) 0xA6, (short) 0xC2, (short) 0x23, (short) 0x3D,
            (short) 0xEE, (short) 0x4C, (short) 0x95, (short) 0x0B, (short) 0x42, (short) 0xFA, (short) 0xC3, (short) 0x4E,
            (short) 0x08, (short) 0x2E, (short) 0xA1, (short) 0x66, (short) 0x28, (short) 0xD9, (short) 0x24, (short) 0xB2,
            (short) 0x76, (short) 0x5B, (short) 0xA2, (short) 0x49, (short) 0x6D, (short) 0x8B, (short) 0xD1, (short) 0x25,
            (short) 0x72, (short) 0xF8, (short) 0xF6, (short) 0x64, (short) 0x86, (short) 0x68, (short) 0x98, (short) 0x16,
            (short) 0xD4, (short) 0xA4, (short) 0x5C, (short) 0xCC, (short) 0x5D, (short) 0x65, (short) 0xB6, (short) 0x92,
            (short) 0x6C, (short) 0x70, (short) 0x48, (short) 0x50, (short) 0xFD, (short) 0xED, (short) 0xB9, (short) 0xDA,
            (short) 0x5E, (short) 0x15, (short) 0x46, (short) 0x57, (short) 0xA7, (short) 0x8D, (short) 0x9D, (short) 0x84,
            (short) 0x90, (short) 0xD8, (short) 0xAB, (short) 0x00, (short) 0x8C, (short) 0xBC, (short) 0xD3, (short) 0x0A,
            (short) 0xF7, (short) 0xE4, (short) 0x58, (short) 0x05, (short) 0xB8, (short) 0xB3, (short) 0x45, (short) 0x06,
            (short) 0xD0, (short) 0x2C, (short) 0x1E, (short) 0x8F, (short) 0xCA, (short) 0x3F, (short) 0x0F, (short) 0x02,
            (short) 0xC1, (short) 0xAF, (short) 0xBD, (short) 0x03, (short) 0x01, (short) 0x13, (short) 0x8A, (short) 0x6B,
            (short) 0x3A, (short) 0x91, (short) 0x11, (short) 0x41, (short) 0x4F, (short) 0x67, (short) 0xDC, (short) 0xEA,
            (short) 0x97, (short) 0xF2, (short) 0xCF, (short) 0xCE, (short) 0xF0, (short) 0xB4, (short) 0xE6, (short) 0x73,
            (short) 0x96, (short) 0xAC, (short) 0x74, (short) 0x22, (short) 0xE7, (short) 0xAD, (short) 0x35, (short) 0x85,
            (short) 0xE2, (short) 0xF9, (short) 0x37, (short) 0xE8, (short) 0x1C, (short) 0x75, (short) 0xDF, (short) 0x6E,
            (short) 0x47, (short) 0xF1, (short) 0x1A, (short) 0x71, (short) 0x1D, (short) 0x29, (short) 0xC5, (short) 0x89,
            (short) 0x6F, (short) 0xB7, (short) 0x62, (short) 0x0E, (short) 0xAA, (short) 0x18, (short) 0xBE, (short) 0x1B,
            (short) 0xFC, (short) 0x56, (short) 0x3E, (short) 0x4B, (short) 0xC6, (short) 0xD2, (short) 0x79, (short) 0x20,
            (short) 0x9A, (short) 0xDB, (short) 0xC0, (short) 0xFE, (short) 0x78, (short) 0xCD, (short) 0x5A, (short) 0xF4,
            (short) 0x1F, (short) 0xDD, (short) 0xA8, (short) 0x33, (short) 0x88, (short) 0x07, (short) 0xC7, (short) 0x31,
            (short) 0xB1, (short) 0x12, (short) 0x10, (short) 0x59, (short) 0x27, (short) 0x80, (short) 0xEC, (short) 0x5F,
            (short) 0x60, (short) 0x51, (short) 0x7F, (short) 0xA9, (short) 0x19, (short) 0xB5, (short) 0x4A, (short) 0x0D,
            (short) 0x2D, (short) 0xE5, (short) 0x7A, (short) 0x9F, (short) 0x93, (short) 0xC9, (short) 0x9C, (short) 0xEF,
            (short) 0xA0, (short) 0xE0, (short) 0x3B, (short) 0x4D, (short) 0xAE, (short) 0x2A, (short) 0xF5, (short) 0xB0,
            (short) 0xC8, (short) 0xEB, (short) 0xBB, (short) 0x3C, (short) 0x83, (short) 0x53, (short) 0x99, (short) 0x61,
            (short) 0x17, (short) 0x2B, (short) 0x04, (short) 0x7E, (short) 0xBA, (short) 0x77, (short) 0xD6, (short) 0x26,
            (short) 0xE1, (short) 0x69, (short) 0x14, (short) 0x63, (short) 0x55, (short) 0x21, (short) 0x0C, (short) 0x7D
        };

        public static byte getSubstitute(byte i) {
            return (byte) SBOX[unsignedByte(i)];
        }

        public static void inplaceSubstitute(byte[] vector) {
            for (int i = 0; i < vector.length; i++) {
                vector[i] = getSubstitute(vector[i]);
            }
        }

        public static void inplaceSubstitute(byte[][] matrix) {
            for (int i = 0; i < matrix.length; i++) {
                inplaceSubstitute(matrix[i]);
            }
        }

        public static byte getInverseSubstitute(byte i) {
            return (byte) INVERSE_SBOX[unsignedByte(i)];
        }

        public static void inplaceInverseSubstitute(byte[] vector) {
            for (int i = 0; i < vector.length; i++) {
                vector[i] = getInverseSubstitute(vector[i]);
            }
        }

        public static void inplaceInverseSubstitute(byte[][] matrix) {
            for (int i = 0; i < matrix.length; i++) {
                inplaceInverseSubstitute(matrix[i]);
            }
        }

        public static short unsignedByte(byte b) {
            return (short) (b & 0xFF);
        }
    }

    public static class ColumnMix {
        private static final byte[][] MIX_COLUMNS_MATRIX = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
        };
        private static final byte[][] MIX_COLUMNS_INVERSE_MATRIX = {
            {0x0E, 0x0B, 0x0D, 0x09},
            {0x09, 0x0E, 0x0B, 0x0D},
            {0x0D, 0x09, 0x0E, 0x0B},
            {0x0B, 0x0D, 0x09, 0x0E}
        };
        private static final int[][] MIX_MATRIX = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
        };
        private static final int[][] INV_MIX_MATRIX = {
            {0x0E, 0x0B, 0x0D, 0x09},
            {0x09, 0x0E, 0x0B, 0x0D},
            {0x0D, 0x09, 0x0E, 0x0B},
            {0x0B, 0x0D, 0x09, 0x0E}
        };

        public static void mix(byte[][] stateMatrix) {
            dot(MIX_COLUMNS_MATRIX, stateMatrix);
        }

        public static void inverseMix(byte[][] stateMatrix) {
            dot(MIX_COLUMNS_INVERSE_MATRIX, stateMatrix);
        }

        public static int[][] mixInt(int[][] state) {
            int[][] newState = new int[4][4];

            for (int col = 0; col < 4; col++) {
                newState[0][col] = (MIX_MATRIX[0][0] * state[0][col]) ^ (MIX_MATRIX[0][1] * state[1][col])
                    ^ (MIX_MATRIX[0][2] * state[2][col]) ^ (MIX_MATRIX[0][3] * state[3][col]);
                newState[1][col] = (MIX_MATRIX[1][0] * state[0][col]) ^ (MIX_MATRIX[1][1] * state[1][col])
                    ^ (MIX_MATRIX[1][2] * state[2][col]) ^ (MIX_MATRIX[1][3] * state[3][col]);
                newState[2][col] = (MIX_MATRIX[2][0] * state[0][col]) ^ (MIX_MATRIX[2][1] * state[1][col])
                    ^ (MIX_MATRIX[2][2] * state[2][col]) ^ (MIX_MATRIX[2][3] * state[3][col]);
                newState[3][col] = (MIX_MATRIX[3][0] * state[0][col]) ^ (MIX_MATRIX[3][1] * state[1][col])
                    ^ (MIX_MATRIX[3][2] * state[2][col]) ^ (MIX_MATRIX[3][3] * state[3][col]);
            }

            return newState;
        }

        public static int[][] inverseMixINt(int[][] state) {
            int[][] newState = new int[4][4];

            for (int col = 0; col < 4; col++) {
                newState[0][col] = (INV_MIX_MATRIX[0][0] * state[0][col]) ^ (INV_MIX_MATRIX[0][1] * state[1][col])
                    ^ (INV_MIX_MATRIX[0][2] * state[2][col]) ^ (INV_MIX_MATRIX[0][3] * state[3][col]);
                newState[1][col] = (INV_MIX_MATRIX[1][0] * state[0][col]) ^ (INV_MIX_MATRIX[1][1] * state[1][col])
                    ^ (INV_MIX_MATRIX[1][2] * state[2][col]) ^ (INV_MIX_MATRIX[1][3] * state[3][col]);
                newState[2][col] = (INV_MIX_MATRIX[2][0] * state[0][col]) ^ (INV_MIX_MATRIX[2][1] * state[1][col])
                    ^ (INV_MIX_MATRIX[2][2] * state[2][col]) ^ (INV_MIX_MATRIX[2][3] * state[3][col]);
                newState[3][col] = (INV_MIX_MATRIX[3][0] * state[0][col]) ^ (INV_MIX_MATRIX[3][1] * state[1][col])
                    ^ (INV_MIX_MATRIX[3][2] * state[2][col]) ^ (INV_MIX_MATRIX[3][3] * state[3][col]);
            }

            return newState;
        }

        public static void main(String[] args) {
            byte[][] bb = new byte[][] {
                {1, 2, 3, 4},
                {5, 6, 7, 8},
                {9, 10, 11, 12},
                {13, 14, 15, 16}
            };
            mix(bb);
            System.out.println(Arrays.deepToString(bb));
            inverseMix(bb);
            System.out.println(Arrays.deepToString(bb));
        }

    }


    public static void dot(byte[][] A, byte[][] B) {
        byte[][] result = new byte[A.length][B[0].length];
        int[][] unsignedMatrix = toUnsignedMatrix(B);
        for (int i = 0; i < A.length; i++) {
            for (int j = 0; j < B[0].length; j++) {
                int thisResults = 0;
                for (int k = 0; k < A.length; k++) {
                    thisResults ^= gfMultiply(A[i][k], B[k][j]);
                }
                result[i][j] = (byte) thisResults;
            }
        }
        System.arraycopy(result, 0, B, 0, B.length);
    }

    private static byte gfMultiply(byte a, byte b) {
        byte product = 0;
        byte mask = 1;
        byte carry = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & mask) != 0) {
                product ^= a;
            }
            carry = (byte) (a & 0x80);
            a <<= 1;
            if (carry != 0) {
                a ^= 0x1B;
            }
            if (product >= 256) {
                product ^= 0x11B;
            }
            mask <<= 1;
        }
        return product;
    }

    public static void dot(int[][] A, int[][] B) {
        int[][] result = new int[A.length][B[0].length];
        for (int i = 0; i < A.length; i++) {
            for (int j = 0; j < B[0].length; j++) {
                int thisResults = B[i][j];
                for (int k = 0; k < A.length; k++) {
                    result[i][j] ^= A[i][k] * B[k][j];
                }
            }
        }
        System.arraycopy(result, 0, B, 0, B.length);
    }

    public static int[][] toUnsignedMatrix(byte[][] bytes) {
        int[][] unsignedBytes = new int[bytes.length][bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < bytes.length; j++) {
                unsignedBytes[i][j] = (bytes[i][j] & 0xff);
            }
        }
        return unsignedBytes;
    }

    public static byte[][] constructStateMatrix(byte[] chunk) {
        if (chunk.length != 16) {
            throw new RuntimeException();
        }
        byte[][] matrix = new byte[4][4];
        int i = 0;
        int j = 0;
        for (byte b : chunk) {
            matrix[i][j] = b;
            if (++j == 4) {
                j = 0;
                i++;
            }
        }
        return matrix;
    }
}
