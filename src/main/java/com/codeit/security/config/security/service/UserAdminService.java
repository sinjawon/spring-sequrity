package com.codeit.security.config.security.service;

import com.codeit.security.config.security.domain.user.User;
import com.codeit.security.config.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserAdminService {

    private final UserRepository userRepository;

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    //    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Transactional
    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
    }

    // PreAuthorize에는 SpEL(Spring Expression Language)을 작성할 수 있습니다.
    // 본인 또는 ADMIN만 정보 수정 가능
//    @PreAuthorize("@boardGuard.checkAccess(#boardId, authentication.name)") -> SpEL로 다른 클래스의 메서드를 호출하는 것도 가능.

    @PreAuthorize("#userId == authentication.principal.user.id or hasRole('ADMIN')")
    @Transactional
    public User updateUser(Long userId, String email) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // email 수정 로직 들어감
        return userRepository.save(user);
    }

    // 메서드 실행 후 권한 확인
    // 반환값을 기반으로 권한 검사 가능
    @PostAuthorize("returnObject.username == authentication.principal.username or hasRole('ADMIN')")
    @Transactional(readOnly = true)
    public User getUserProfile(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
    }
    }



