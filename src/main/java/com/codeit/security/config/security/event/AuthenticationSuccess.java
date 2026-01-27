package com.codeit.security.config.security.event;

import com.codeit.security.config.security.security.CustomUserDetails;
import jakarta.persistence.Column;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Slf4j
@Component
public class AuthenticationSuccess {
    @EventListener
    public void onApplicationSuccess(AuthenticationSuccessEvent event){
        Object principal =event.getAuthentication().getPrincipal();

        //이렇게하면 바로 변수선언하면 어떻게되지  바로 변환가능
        if(principal instanceof CustomUserDetails userDetails){
           log.info("===로그성공===");
           log.info("사용자: {}", userDetails.getUsername());
           log.info("시간 : {}", LocalDateTime.now());
           //만약권한이 여러개면 쭉나열가능하다
           log.info("권한: {}", userDetails.getAuthorities());
           log.info("==================");
        }
    }
}
