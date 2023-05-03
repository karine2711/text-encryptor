package com.cybersec.encryptor.textencryptor.controller;


import com.cybersec.encryptor.textencryptor.impl.ECC.EllipticCurveEncryptor;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
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
    public ResponseEntity<String> encrypt(@RequestBody(required = true) @Valid ECCEncryptDto dto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().get(0).getDefaultMessage();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(encryptor.encrypt(dto.message, dto.publicKey));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody(required = true) @Valid ECCDecryptDto dto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().get(0).getDefaultMessage();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(encryptor.decrypt(dto.message, dto.privateKey));
    }

    record ECCEncryptDto(@NotBlank(message = "Parameter \"message\" is required!") String message, @NotBlank(message = "Parameter \"publicKey\" is required!")String publicKey) {
    }

    record ECCDecryptDto(@NotBlank(message = "Parameter \"message\" is required!") String message, @NotBlank(message = "Parameter \"privateKey\" is required!") String privateKey) {
    }
}
