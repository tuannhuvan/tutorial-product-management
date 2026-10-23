package com.fptaptech.auth.security;

import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.UserRepository;
import com.fptaptech.auth.user.UserStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Slf4j
public class DatabaseUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public DatabaseUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        AppUser user = userRepository.findByUsernameOrEmail(usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Tài khoản hoặc mật khẩu không chính xác hoặc chưa được kích hoạt."));

        // Auto unlock after 15 minutes of being LOCKED
        if (user.getStatus() == UserStatus.LOCKED && user.getLockTime() != null) {
            if (user.getLockTime().plusMinutes(15).isBefore(LocalDateTime.now())) {
                log.info("User {} lock duration (15 mins) expired. Auto unlocking to ACTIVE.", user.getUsername());
                user.setStatus(UserStatus.ACTIVE);
                user.setFailedAttempts(0);
                user.setLockTime(null);
                user = userRepository.save(user);
            }
        }

        return new CustomUserDetails(user);
    }
}
