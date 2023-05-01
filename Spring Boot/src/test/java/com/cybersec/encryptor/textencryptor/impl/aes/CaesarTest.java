package com.cybersec.encryptor.textencryptor.impl.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.cybersec.encryptor.textencryptor.excpetion.AlgorithmInstantiationException;
import com.cybersec.encryptor.textencryptor.impl.caesar.Caesar;
import org.junit.jupiter.api.Test;

class CaesarTest {

    @Test
    void givenValidKey_encrypt() {
        var caesar = new Caesar(2);
        var encryptedText = caesar.encrypt("aBcdEf");
        assertEquals("cDefGh", encryptedText);
    }

    @Test
    void givenValidKey_decrypt() {
        var caesar = new Caesar(2);
        var decryptedText = caesar.decrypt("cDefGh");
        assertEquals("aBcdEf", decryptedText);
    }

    @Test
    void givenInvalidKey_throwException() {
        assertThrows(AlgorithmInstantiationException.class, () -> new Caesar(50));
    }
}