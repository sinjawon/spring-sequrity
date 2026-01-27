package com.codeit.security.config.security.controller;

import com.codeit.security.config.security.dto.requset.SignupRequest;
import com.codeit.security.config.security.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class SignupController {

    private  final UserService userService;


    @GetMapping("/signup")
    public String signupForm(Model model){
        //dto객체 생성해서 리퀘스트를 모델에담아 전달
        model.addAttribute("signupRequest", new SignupRequest());

        return "signup";
    }

    @PostMapping("/signup")
    public String signupForm(@Valid @ModelAttribute SignupRequest request,
                             BindingResult bindingResult){

        //유효성 검증 실패하면 사인업 html 전환
       if(bindingResult.hasErrors()){
           return "signup";
       }
         userService.signup(request);
          return "redirect:/login";
        }
}
