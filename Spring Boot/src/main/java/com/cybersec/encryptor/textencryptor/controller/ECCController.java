package com.cybersec.encryptor.textencryptor.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/ecc")
public class ECCController {


    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody String text) {
        return ResponseEntity.ok().build();
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody String text) {
        return ResponseEntity.ok().build();
    }
}
