package com.cybersec.encryptor.textencryptor.controller;

import com.cybersec.encryptor.textencryptor.impl.caesar.Caesar;
import javax.validation.Valid;
import javax.validation.constraints.Digits;
import javax.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/caesar")
public class CaesarController {

    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody(required = true) @Valid CaesarDto caesarDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().get(0).getDefaultMessage();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(new Caesar(Integer.parseInt(caesarDto.key())).encrypt(caesarDto.message));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody(required = true) @Valid CaesarDto caesarDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().get(0).getDefaultMessage();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
        }
        return ResponseEntity.ok(new Caesar(Integer.parseInt(caesarDto.key())).decrypt(caesarDto.message()));
    }

    record CaesarDto(@NotBlank(message = "Parameter \"message\" is required!") String message,
                     @NotBlank(message = "Parameter \"key\" is required!") @Digits(integer = 2, fraction = 0, message = "The key for Caesar algorithm must be an integer!") String key) {
    }
}
