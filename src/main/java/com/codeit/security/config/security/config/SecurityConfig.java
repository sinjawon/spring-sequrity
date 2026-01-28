package com.codeit.security.config.security.config;

import com.codeit.security.config.security.filtrt.IpCheckFilter;
import com.codeit.security.config.security.filtrt.RequsetIdFilter;
import com.codeit.security.config.security.filtrt.RequsetLoggingFilter;
import com.codeit.security.config.security.security.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final RequsetLoggingFilter requsetLoggingFilter;
    private final IpCheckFilter ipCheckFilter;
    private final RequsetIdFilter requsetIdFilter;

    //Spring Security Filter Chain 보안필터 체인을 구성하고 조리밯는역할 절차 규칙 설정
    //원하는 로직을 조리밯면된다
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();

    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http     //인증 필터 로깅 동적잔에 필터 추가  UsernamePasswordAuthenticationFilter.class 시큐리티 가본
                .addFilterBefore(requsetIdFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(ipCheckFilter,RequsetIdFilter.class)
                .addFilterAfter(requsetLoggingFilter, IpCheckFilter.class)
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
                        .deleteCookies("JSESSIONID")// 이넘이?
                        .permitAll())
                //csrf도 사용하지않는다
                .csrf(csrf->csrf.ignoringRequestMatchers("/h2-console/**"))
                .headers(headers->headers
                .frameOptions(frame-> frame.sameOrigin())

                );


        return http.build();
    }
}
