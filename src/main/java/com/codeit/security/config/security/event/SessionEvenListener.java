package com.codeit.security.config.security.event;

import jakarta.servlet.http.HttpSession;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.session.HttpSessionCreatedEvent;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

@Slf4j
@Component
public class SessionEvenListener {

    //데이터타임포메터
    //사용하는 시스템의 디폴트 타임좆
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(DateTimeFormatter.ISO_OFFSET_DATE_TIME.getZone());

    @EventListener
    public void onSessionCreated(HttpSessionCreatedEvent event){
        HttpSession session = event.getSession();
        log.info("===새 세션 생성===");
        log.info("세션 id: {}", session.getId());
        log.info("생성 시간: {}", FORMATTER.format(Instant.ofEpochMilli(session.getCreationTime())));
        log.info("최대 비활성 시간:{} 분",session.getMaxInactiveInterval() / 60);//


    }
    @EventListener
    public void onSessionDestroyed(HttpSessionDestroyedEvent event){
        HttpSession session = event.getSession();

         log.info("===새 세션 소멸===");
        log.info("세션 id: {}", session.getId());
        //얻고자하는 데이터를 문자열로  시큐리티컨텍스트저장하는이름은 항상
        //저에해져있다
        //세션
        //어떤객체든받한다 ? Object attribute =  이것보다는 SecurityContext
        SecurityContext context
                = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

        if(context != null && context.getAuthentication() != null){

            log.info("사용자: {}",context.getAuthentication().getName());
            log.info("로그아웃시간 : {}", Instant.now());
        }
    }

}
