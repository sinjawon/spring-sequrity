package com.codeit.security.config.security.service;


import org.springframework.stereotype.Service;

@Service("boardGuard")
public class BoardSecurityService {

    public boolean CheckAccess(Long boardId, String UserName){
        return true;
    }
}
