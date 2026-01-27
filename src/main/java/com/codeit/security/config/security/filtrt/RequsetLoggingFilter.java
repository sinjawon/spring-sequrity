package com.codeit.security.config.security.filtrt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class RequsetLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        //요청방식 리퀘스트 유알엘 아이피주소
        long l = System.currentTimeMillis();
        log.info("Request: {} {} form {}", request.getMethod(), request.getRequestURI(), request.getRemoteAddr());

        //다음필터로 요청 응답 객체를 전달
        //g하고자하는 요청이끝나면 보내줘라
        try {
            filterChain.doFilter(request, response);
        }finally {
            long l1 = System.currentTimeMillis() - l;
            log.info("Response: {} {} -Status{} -Duration {}ms",
                    request.getMethod(),
                    request.getRequestURI(),
                    response.getStatus(),
                    l1);
        }


    }
}
