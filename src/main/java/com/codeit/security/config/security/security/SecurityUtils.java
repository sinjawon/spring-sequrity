package com.codeit.security.config.security.security;

import com.codeit.security.config.security.domain.user.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class SecurityUtils {


    //현재 로그인 한 사용자의 username을 반환
    public static Optional<User> getCurrentUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()){
            return Optional.empty();
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof CustomUserDetails){
            return Optional.of(((CustomUserDetails)principal).getUser());
        }

        return Optional.empty();
    }
}
