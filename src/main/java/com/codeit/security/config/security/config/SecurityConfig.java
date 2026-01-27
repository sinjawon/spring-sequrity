package com.codeit.security.config.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    //Spring Security Filter Chain 보안필터 체인을 구성하고 조리밯는역할 절차 규칙 설정
    //원하는 로직을 조리밯면된다
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();

    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth->auth
                .requestMatchers("/","/h2-console/**","/signup","/css/**","/js/**").permitAll()
                .anyRequest().authenticated()
                )
                //폼설정은 rest에서 사용안해
                .formLogin(form->form
                        .loginPage("/login")
                        .permitAll())
                .logout(logout->logout
                        .logoutUrl("/logout")
                        .permitAll())
                //csrf도 사용하지않는다
                .csrf(csrf->csrf.ignoringRequestMatchers("/h2-console/**"))
                .headers(headers->headers
                .frameOptions(frame-> frame.sameOrigin())

                );


        return http.build();
    }
}
