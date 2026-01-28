package com.codeit.security.config.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
   @GetMapping("csrf-token")
    public ResponseEntity<Void> getcsrfToken(){
       //내용없어도ㅗ딘다
       //api가 호출되는 과정에서 필터가 동작해 자동으로 쿠키를 구워준다
       return ResponseEntity.ok().build();
    }
    @PostMapping
    public ResponseEntity<String> login(){
        return ResponseEntity.ok().build();
    }
}
