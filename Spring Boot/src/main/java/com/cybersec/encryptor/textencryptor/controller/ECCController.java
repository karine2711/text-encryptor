package com.cybersec.encryptor.textencryptor.controller;


import com.cybersec.encryptor.textencryptor.impl.ECC.EllipticCurveEncryptor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/ecc")
public class ECCController {

    private final EllipticCurveEncryptor encryptor = EllipticCurveEncryptor.DEFAULT;

    @GetMapping("/keys")
    public ResponseEntity<EllipticCurveEncryptor.KeySet> keySet() {
        return ResponseEntity.ok(encryptor.generateKeySet());
    }

    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody ECCEncryptDto dto) {
        return ResponseEntity.ok(encryptor.encrypt(dto.message, dto.publicKey));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody ECCDecryptDto dto) {
        return ResponseEntity.ok(encryptor.decrypt(dto.message, dto.privateKey));
    }

    record ECCEncryptDto( String message, String publicKey) {
    }

    record ECCDecryptDto( String message, String privateKey) {
    }
}
