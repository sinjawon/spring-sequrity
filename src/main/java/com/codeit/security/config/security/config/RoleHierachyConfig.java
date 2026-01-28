package com.codeit.security.config.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;

@Configuration
public class RoleHierachyConfig {

    //권한 계층 구조 정의
    //   ROLE_ADMIN > ROLE_MANAGER > ROLE_USER
    @Bean
    public RoleHierarchy roleHierarchy(){
    //    RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();

        String hierarchy = """
                ROLE_ADMIN > ROLE_MANAGER
                ROLE_MANAGER > ROLE_USER
                """;
        //roleHierarchy.setHierarchy(hierarchy);
        return RoleHierarchyImpl.fromHierarchy(hierarchy);
    }


    //메서드 보안에 권한 계층을적용
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy){
        DefaultMethodSecurityExpressionHandler expressionHandler
                = new DefaultMethodSecurityExpressionHandler();

        expressionHandler.setRoleHierarchy(roleHierarchy);
        return expressionHandler;
    }
}
