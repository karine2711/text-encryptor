package com.cybersec.encryptor.textencryptor.controller;

import com.cybersec.encryptor.textencryptor.impl.aes.AES128;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/aes")
public class AESController {


    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody(required = true) @Valid AesDto aesDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().get(0).getDefaultMessage();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(new AES128(aesDto.byteMasterKey()).encrypt(aesDto.message()));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody(required = true) @Valid AesDto aesDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().get(0).getDefaultMessage();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(new AES128(aesDto.byteMasterKey()).decrypt(aesDto.message()));
    }


    record AesDto(@NotBlank(message = "Parameter \"message\" is required!") String message,
                  @NotBlank(message = "Parameter \"masterKey\" is required!") String masterKey) {
        public byte[] byteMasterKey() {
            byte[] ogKey = masterKey.getBytes(StandardCharsets.UTF_8);
            return Arrays.copyOf(ogKey, 16);
        }
    }

}
