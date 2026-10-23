package com.fptaptech.auth;

import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.Role;
import com.fptaptech.auth.user.RoleRepository;
import com.fptaptech.auth.user.UserRepository;
import com.fptaptech.auth.user.UserStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
@Slf4j
public class AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

    @Bean
    public CommandLineRunner initDefaultAdmin(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder
    ) {
        return args -> {
            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_ADMIN").build()));
            Role lecturerRole = roleRepository.findByName("ROLE_LECTURER")
                    .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_LECTURER").build()));
            Role studentRole = roleRepository.findByName("ROLE_STUDENT")
                    .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_STUDENT").build()));

            if (!userRepository.existsByUsername("admin")) {
                Set<Role> roles = new HashSet<>();
                roles.add(adminRole);
                roles.add(lecturerRole);

                AppUser admin = AppUser.builder()
                        .username("admin")
                        .email("admin@fptaptech.edu.vn")
                        .passwordHash(passwordEncoder.encode("Admin@FPT2026!"))
                        .status(UserStatus.ACTIVE)
                        .enabled(true)
                        .failedAttempts(0)
                        .createdAt(LocalDateTime.now())
                        .roles(roles)
                        .build();

                userRepository.save(admin);
                log.info("Initialized default system admin account: username='admin', password='Admin@FPT2026!'");
            }
        };
    }
}
