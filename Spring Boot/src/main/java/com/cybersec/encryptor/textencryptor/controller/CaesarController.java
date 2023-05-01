package com.cybersec.encryptor.textencryptor.controller;

import com.cybersec.encryptor.textencryptor.impl.caesar.Caesar;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/caesar")
public class CaesarController {

    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody CaesarDto caesarDto) {
        return ResponseEntity.ok(new Caesar(caesarDto.getKey()).encrypt(caesarDto.text));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody CaesarDto caesarDto) {
        return ResponseEntity.ok(new Caesar(caesarDto.getKey()).decrypt(caesarDto.getText()));
    }

    private static class CaesarDto {
        private String text;
        private int key;

        public String getText() {
            return text;
        }

        public void setText(String text) {
            this.text = text;
        }

        public int getKey() {
            return key;
        }

        public void setKey(int key) {
            this.key = key;
        }
    }
}
