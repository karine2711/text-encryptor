package com.cybersec.encryptor.textencryptor.controller;

import com.cybersec.encryptor.textencryptor.impl.aes.AES128;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/aes")
public class AESController {


    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody AesDto aesDto) {
        return ResponseEntity.ok(new AES128(aesDto.getMasterKey()).encrypt(aesDto.getText()));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody AesDto aesDto) {
        return ResponseEntity.ok(new AES128(aesDto.getMasterKey()).decrypt(aesDto.getText()));
    }


    private static class AesDto {
        private String masterKey;
        private String text;

        public byte[] getMasterKey() {
            byte[] ogKey=masterKey.getBytes(StandardCharsets.UTF_8);
            return Arrays.copyOf(ogKey,16);
        }

        public void setMasterKey(String masterKey) {
            this.masterKey = masterKey;
        }

        public String getText() {
            return text;
        }

        public void setText(String text) {
            this.text = text;
        }
    }
}
