package com.codeit.security.config.security.service;

import com.codeit.security.config.security.domain.user.User;
import com.codeit.security.config.security.dto.requset.SignupRequest;
import com.codeit.security.config.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordencoder;

    @Transactional
    public User signup(SignupRequest request) {
        if (userRepository.existsByUsername(request.getUsername())){
            throw new IllegalThreadStateException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())){
            throw new IllegalThreadStateException("Email already exists");
        }
        //비밀번호 암호화
        String encodePassword = passwordencoder.encode(request.getPassword());

        User user = User.builder()
                .username(request.getUsername())
                .password(encodePassword)
                .email(request.getEmail())
                .role("USER")
                .build();

        return userRepository.save(user);
    }
}
