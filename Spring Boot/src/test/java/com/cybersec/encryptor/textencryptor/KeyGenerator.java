package com.cybersec.encryptor.textencryptor;

import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyGenerator {
         public static byte[] generate() {
            SecureRandom random = new SecureRandom();
            byte[] keyBytes = new byte[16];
            random.nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            return key.getEncoded();
        }

}
