package com.codeit.security.config.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;


//프론트엔드와 배겡ㄴ드가 분리되어 있는 경우 , 브라우저는 보안상 다른 출처의 요청을 차단해 버립니다
//브라우조는 same-roin policyy 준수 orifin 프로토콜 + 도메인 + 포트
@Configuration
public class CorsConfig {

    @Bean("corsConfigSource")
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();

        // 허용할 출처 (Origin)
        configuration.setAllowedOrigins(List.of(
                "http://localhost:3000",     // React 개발 서버
                "http://localhost:5173",     // Vite 개발 서버
                "https://yourdomain.com"     // 운영 도메인
        ));

        // 허용할 HTTP 메서드
        //options 실제 요청 전에 사전요청(preflight request)보내는데 , 이 전송방식이 OPTIONS 이게 없으면
        //팡팡터진다
        configuration.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        ));

        // 허용할 헤더
        configuration.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "X-CSRF-TOKEN"
        ));

        // 자격 증명 (쿠키, 인증 헤더) 허용
        configuration.setAllowCredentials(true);

        // Preflight 요청 캐시 시간 (초)
        configuration.setMaxAge(3600L);

        // 노출할 헤더 (프론트엔드에서 읽을 수 있는 헤더)
        configuration.setExposedHeaders(List.of(
                "Authorization",
                "X-Request-ID"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

}
