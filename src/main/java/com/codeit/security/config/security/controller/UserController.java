package com.codeit.security.config.security.controller;

import com.codeit.security.config.security.domain.user.User;
import com.codeit.security.config.security.security.CustomUserDetails;
import com.codeit.security.config.security.security.SecurityUtils;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/user")
public class UserController {
   //방법1: securityUstils 사용
    @GetMapping("/profile")
    public String profile(Model model){
        User user = SecurityUtils.getCurrentUser()
                .orElseThrow(() -> new IllegalArgumentException("로그인필요"));
        log.info("user: {}", user);
        model.addAttribute("user", user);
        return "user/profile";
    }

    //방법2 : @어노테ㅣ이션 사용 @AuthenticationPrincipal 사용
    @GetMapping("/info")
    @ResponseBody
    public Map<String, Object> userInfo(@AuthenticationPrincipal CustomUserDetails customUserDetails){
        User user = customUserDetails.getUser();

        Map<String, Object> info = new HashMap<>();
        info.put("id", user.getId());
        info.put("username", user.getUsername());
        info.put("email", user.getEmail());
        info.put("role", user.getRole());

        return info;
    }
}
