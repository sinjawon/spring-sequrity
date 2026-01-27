package com.codeit.security.config.security.config;

import com.codeit.security.config.security.event.AuthenticationFailureListner;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.stereotype.Controller;

@Configuration
public class EventConfig {


    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(
            ApplicationEventPublisher applicationEventPublisher
    ) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }
}
