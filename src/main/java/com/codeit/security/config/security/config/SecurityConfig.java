package com.codeit.security.config.security.config;

import com.codeit.security.config.security.filtrt.IpCheckFilter;
import com.codeit.security.config.security.filtrt.RequsetIdFilter;
import com.codeit.security.config.security.filtrt.RequsetLoggingFilter;
import com.codeit.security.config.security.security.CustomAccessDeniedHandler;
import com.codeit.security.config.security.security.CustomAuthenticationEntryPoint;
import com.codeit.security.config.security.security.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
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
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           RoleHierarchy roleHierarchy,
                                           CustomAccessDeniedHandler accessDeniedHandler,
                                           CustomAuthenticationEntryPoint customAuthenticationEntryPoint) throws Exception {

        http     //인증 필터 로깅 동적잔에 필터 추가  UsernamePasswordAuthenticationFilter.class 시큐리티 가본
                .addFilterBefore(requsetIdFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(ipCheckFilter,RequsetIdFilter.class)
                .addFilterAfter(requsetLoggingFilter, IpCheckFilter.class)
                .authorizeHttpRequests(auth->auth
                 // 공개 접근 (인증 불필여 )
                 //.anonymous()로그인하지 않은 사용자만 허용
                .requestMatchers("/","/signup","/login").permitAll()
                .requestMatchers("/css/**","/js/**","/public/**").permitAll()
                .requestMatchers("/h2-console/**").permitAll()

                 //ADMIN 권한 필
                 //hasRole("ADMIN")" :"ROLE_ADMIN" 권한확인 -> 보통이넘을확용
                 //hasAuthority("ROLE_ADMIN"): 정확히 롤 언더바확인
           //     .requestMatchers("/admin/**").hasRole("ADMIN")

                //MANAGER또는 ADMIN 권한 필요
                .requestMatchers("/manager/**").hasAnyRole("MANAGER","ADMIN")

                 //USER권한필요
                .requestMatchers("/user/**").hasRole("USER")

                 //나머지 인증만 필요 (권한무관)
                .anyRequest().authenticated()
                )
                .exceptionHandling(exception->exception
                        .authenticationEntryPoint(customAuthenticationEntryPoint)//인증
                        .accessDeniedHandler(accessDeniedHandler)//인가
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
