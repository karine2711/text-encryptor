package com.cybersec.encryptor.textencryptor.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.cybersec.encryptor.textencryptor.KeyGenerator;
import com.cybersec.encryptor.textencryptor.impl.aes.KeyScheduler;
import org.junit.jupiter.api.Test;

class KeySchedulerTest {

    @Test
    void getNextKey() {
        byte[] key = KeyGenerator.generate();

        var scheduler = new KeyScheduler(key);
        var scheduler2 = new KeyScheduler(key);
        assertArrayEquals(scheduler.getNextKey(),scheduler2.getNextKey());
        assertArrayEquals(scheduler.getNextKey(),scheduler2.getNextKey());
    }
}