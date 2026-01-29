package com.codeit.security.config.security.security;

import com.codeit.security.config.security.domain.user.User;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

@Getter
@RequiredArgsConstructor
//스프링 시큐리티는 우리의 User 엔티티를 전혀 모른다 . UserDetails라는 양식밖에 모름
//우리의 User 정보를 USerDetails라는 양식에 맞춰서 포장한 객체가 CustomUserDetails
public class CustomUserDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //유저의 권한(Role)을 리턴하는 곳
        //GrantedAuthority 형태로 변환해서 저장 ,접두어로 role를 붙여서 저장
        //안그러면 ??
        return List.of(new SimpleGrantedAuthority("ROLE_"+user.getRole()));
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    //나중에 컨트롤러에서 필요할 때 진짜 유저 정보를 꺼내기 위한 getter
    public User getUser(){
        return user;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CustomUserDetails that = (CustomUserDetails) o;
        // DB의 유니크한 ID나 username으로 비교
        return Objects.equals(user.getUsername(), that.user.getUsername());
    }

    @Override
    public int hashCode() {
        return Objects.hash(user.getUsername());
    }
}
