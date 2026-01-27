package com.codeit.security.config.security.event;

import com.codeit.security.config.security.security.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Slf4j
@Component
public class AuthenticationFailureListner {

    @EventListener
    public void onApplicationSuccess(AbstractAuthenticationFailureEvent event){
        //성공은 가능한데 실패는
        String name = event.getAuthentication().getName();
        String reason = event.getException().getMessage();

        log.info("===로그인 실패===");
        log.info("사용자: {}", name);
        log.info("이유: {}", reason);
        log.info("시간 : {}", LocalDateTime.now());

       if(event instanceof AuthenticationFailureBadCredentialsEvent){

           //비밀번호오류
           log.info("=========비밀번호오류=========");
       }else if (event instanceof AuthenticationFailureDisabledEvent){
           //비밀번호 오류 (실패횟수 체크 계정잠금 로직 가능)
           log.warn("비활성화된 계정!");
       }
    }
}
