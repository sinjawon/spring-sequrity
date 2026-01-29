package com.codeit.security.config.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorController {

    @GetMapping("/access-denied")
    public String error(){
        return "error/access-denied";
    }

    @GetMapping("session-expired")
    public String expired(){
        return "error/session-expired";
    }
}
