package com.codeit.security.config.security.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;

import java.util.function.Supplier;

public class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {

    //토큰값을 암호화 하지않고 그대로 처리하는 객체
    private final CsrfTokenRequestAttributeHandler plain =  new CsrfTokenRequestAttributeHandler();
    //토근값을 암호화 해서 변장시키고 , 들어온 값으 ㅣ변장을 풀어서 확인하는 객체
    private final CsrfTokenRequestAttributeHandler xor =  new XorCsrfTokenRequestAttributeHandler();

    @Override
    //프론트 엔드에서 / api/auth/csrf-token을 호출해서 토큰을 달라고 요청해도 스프링은 당장 사용하는것이아니면 토큰을생성하지않는ㄴ다
    //요청이 들어오면 강제로 터큰 생성을 해서 쿠키에 담으라고 명령한다 -> response 헤더에 set-cookie라는 이름으로 토큰이 실려 나간다.

    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
        //기본적인 로직은 보안담당자(xor)에게 처리를 맡김
        this.xor.handle(request, response, csrfToken);

        //토큰을 강제로 꺼낸다
        csrfToken.get();
    }

    //프론트 엔드가 토큰을 보내면 어떻게 해석할 지 결정하는 메서드
    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
        //1. 요청 헤더에 실제 토큰값이 들어있는 지 확인한다
        String headerValue = request.getHeader(csrfToken.getHeaderName());
        //스프링프레임워크 유틸
        //상황에따라 다른 담당자를 불러오겠다
        //해더에 값이 있다 0> 프론트엔드가 쿠키에서 읽어 직접보낸거다
        //헤더값이 없다  -> 옛날 방식 form 이거나 다른 요청일 수 있다
        return (StringUtils.hasText(headerValue) ? this.plain : this.xor).resolveCsrfTokenValue(request, csrfToken);
    }
}
