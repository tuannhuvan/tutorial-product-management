package com.fptaptech.auth.user;

import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.EmailService;
import com.fptaptech.auth.security.SessionManagementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;

@Service
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final EmailTokenRepository emailTokenRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordPolicyService passwordPolicyService;
    private final AuditService auditService;
    private final EmailService emailService;
    private final SessionManagementService sessionManagementService;
    private final PasswordEncoder passwordEncoder;

    private final SecureRandom secureRandom = new SecureRandom();

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       EmailTokenRepository emailTokenRepository,
                       PasswordHistoryRepository passwordHistoryRepository,
                       PasswordPolicyService passwordPolicyService,
                       AuditService auditService,
                       EmailService emailService,
                       SessionManagementService sessionManagementService,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.emailTokenRepository = emailTokenRepository;
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.passwordPolicyService = passwordPolicyService;
        this.auditService = auditService;
        this.emailService = emailService;
        this.sessionManagementService = sessionManagementService;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public AppUser registerStudent(String username, String email, String password, String ip, String ua) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Tên đăng nhập đã tồn tại trong hệ thống.");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Địa chỉ email đã được sử dụng.");
        }

        passwordPolicyService.validate(password, username, email, null, passwordEncoder);

        Role studentRole = roleRepository.findByName("ROLE_STUDENT")
                .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_STUDENT").build()));

        String encodedPassword = passwordEncoder.encode(password);

        AppUser user = AppUser.builder()
                .username(username)
                .email(email)
                .passwordHash(encodedPassword)
                .status(UserStatus.PENDING)
                .enabled(true)
                .failedAttempts(0)
                .createdAt(LocalDateTime.now())
                .roles(new HashSet<>(Collections.singletonList(studentRole)))
                .build();

        user = userRepository.save(user);

        // Save password history
        passwordHistoryRepository.save(PasswordHistory.builder()
                .user(user)
                .passwordHash(encodedPassword)
                .createdAt(LocalDateTime.now())
                .build());

        // Create Verification Token
        String plainToken = generateSecureToken();
        String tokenHash = sha256Hex(plainToken);

        emailTokenRepository.save(EmailToken.builder()
                .user(user)
                .tokenHash(tokenHash)
                .tokenType(EmailToken.TYPE_VERIFY_EMAIL)
                .expiresAt(LocalDateTime.now().plusHours(24))
                .used(false)
                .build());

        auditService.logEvent(user.getId(), username, "REGISTER_SUCCESS", ip, ua, "Student registration pending email verification.");

        // Dispatch verification email
        emailService.sendVerificationEmail(email, plainToken);

        return user;
    }

    @Transactional
    public boolean verifyEmail(String plainToken, String ip, String ua) {
        if (plainToken == null || plainToken.isBlank()) {
            return false;
        }

        String tokenHash = sha256Hex(plainToken);
        Optional<EmailToken> optToken = emailTokenRepository.findByTokenHashAndTokenTypeAndUsedFalse(
                tokenHash, EmailToken.TYPE_VERIFY_EMAIL
        );

        if (optToken.isEmpty()) {
            log.warn("Invalid or already used verification token: {}", plainToken);
            return false;
        }

        EmailToken emailToken = optToken.get();
        if (emailToken.isExpired()) {
            log.warn("Expired verification token for user: {}", emailToken.getUser().getUsername());
            return false;
        }

        emailToken.setUsed(true);
        emailTokenRepository.save(emailToken);

        AppUser user = emailToken.getUser();
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        auditService.logEvent(user.getId(), user.getUsername(), "EMAIL_VERIFIED", ip, ua, "Account email successfully verified.");
        return true;
    }

    @Transactional
    public boolean resendVerificationEmail(String email, String ip, String ua) {
        Optional<AppUser> optUser = userRepository.findByEmail(email);
        if (optUser.isEmpty()) return true; // Uniform response

        AppUser user = optUser.get();
        if (user.getStatus() != UserStatus.PENDING) return true;

        // Rate limit: max 3/hour
        long recentCount = emailTokenRepository.countRecentTokensByUser(
                user, EmailToken.TYPE_VERIFY_EMAIL, LocalDateTime.now().minusHours(1)
        );
        if (recentCount >= 3) {
            log.warn("Resend email rate limit exceeded for user: {}", user.getUsername());
            throw new IllegalStateException("Bạn đã yêu cầu gửi lại email quá 3 lần trong vòng 1 giờ. Vui lòng thử lại sau.");
        }

        emailTokenRepository.invalidateTokensByUserAndType(user, EmailToken.TYPE_VERIFY_EMAIL);

        String plainToken = generateSecureToken();
        String tokenHash = sha256Hex(plainToken);

        emailTokenRepository.save(EmailToken.builder()
                .user(user)
                .tokenHash(tokenHash)
                .tokenType(EmailToken.TYPE_VERIFY_EMAIL)
                .expiresAt(LocalDateTime.now().plusHours(24))
                .used(false)
                .build());

        emailService.sendVerificationEmail(user.getEmail(), plainToken);
        auditService.logEvent(user.getId(), user.getUsername(), "RESEND_VERIFICATION", ip, ua, "Resent verification email.");
        return true;
    }

    @Transactional
    public void requestPasswordReset(String email, String ip, String ua) {
        // Uniform Response (F3): Always finish silently regardless of existence
        Optional<AppUser> optUser = userRepository.findByEmail(email);
        if (optUser.isEmpty()) {
            log.info("Password reset requested for non-existing email: {}", email);
            return;
        }

        AppUser user = optUser.get();
        if (user.getStatus() == UserStatus.DISABLED) {
            log.warn("Password reset requested for DISABLED user: {}", user.getUsername());
            return;
        }

        emailTokenRepository.invalidateTokensByUserAndType(user, EmailToken.TYPE_RESET_PASSWORD);

        String plainToken = generateSecureToken();
        String tokenHash = sha256Hex(plainToken);

        emailTokenRepository.save(EmailToken.builder()
                .user(user)
                .tokenHash(tokenHash)
                .tokenType(EmailToken.TYPE_RESET_PASSWORD)
                .expiresAt(LocalDateTime.now().plusMinutes(30))
                .used(false)
                .build());

        auditService.logEvent(user.getId(), user.getUsername(), "PASSWORD_RESET_REQUESTED", ip, ua, "Reset link sent.");
        emailService.sendPasswordResetEmail(user.getEmail(), plainToken);
    }

    @Transactional
    public boolean resetPassword(String plainToken, String newPassword, String ip, String ua) {
        if (plainToken == null || plainToken.isBlank()) return false;

        String tokenHash = sha256Hex(plainToken);
        Optional<EmailToken> optToken = emailTokenRepository.findByTokenHashAndTokenTypeAndUsedFalse(
                tokenHash, EmailToken.TYPE_RESET_PASSWORD
        );

        if (optToken.isEmpty() || optToken.get().isExpired()) {
            return false;
        }

        EmailToken emailToken = optToken.get();
        AppUser user = emailToken.getUser();

        passwordPolicyService.validate(newPassword, user.getUsername(), user.getEmail(), user, passwordEncoder);

        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPasswordHash(encodedPassword);
        user.setFailedAttempts(0);
        user.setLockTime(null);
        if (user.getStatus() == UserStatus.LOCKED) {
            user.setStatus(UserStatus.ACTIVE);
        }
        userRepository.save(user);

        emailToken.setUsed(true);
        emailTokenRepository.save(emailToken);

        passwordHistoryRepository.save(PasswordHistory.builder()
                .user(user)
                .passwordHash(encodedPassword)
                .createdAt(LocalDateTime.now())
                .build());

        // F3: Hủy tất cả các phiên làm việc cũ và Remember-me tokens
        sessionManagementService.terminateAllSessions(user.getUsername());

        auditService.logEvent(user.getId(), user.getUsername(), "PASSWORD_RESET_SUCCESS", ip, ua, "Password successfully reset and sessions terminated.");
        return true;
    }

    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword, String currentSessionId, String ip, String ua) {
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng."));

        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("Mật khẩu hiện tại không chính xác.");
        }

        passwordPolicyService.validate(newPassword, user.getUsername(), user.getEmail(), user, passwordEncoder);

        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPasswordHash(encodedPassword);
        userRepository.save(user);

        passwordHistoryRepository.save(PasswordHistory.builder()
                .user(user)
                .passwordHash(encodedPassword)
                .createdAt(LocalDateTime.now())
                .build());

        // F9: Hủy tất cả các phiên đăng nhập khác, giữ lại phiên hiện tại
        sessionManagementService.terminateAllSessionsExceptCurrent(username, currentSessionId);

        auditService.logEvent(user.getId(), username, "PASSWORD_CHANGED", ip, ua, "Password changed. Remote sessions invalidated.");
    }

    @Transactional
    public void handleLoginFailure(String username, String ip, String ua) {
        Optional<AppUser> optUser = userRepository.findByUsernameOrEmail(username);

        if (optUser.isPresent()) {
            AppUser user = optUser.get();
            if (user.getStatus() == UserStatus.ACTIVE) {
                int attempts = user.getFailedAttempts() + 1;
                user.setFailedAttempts(attempts);

                // F5: 5 lần sai -> Khóa 15 phút
                if (attempts >= 5) {
                    user.setStatus(UserStatus.LOCKED);
                    user.setLockTime(LocalDateTime.now());
                    log.warn("Account {} is now LOCKED due to 5 consecutive failed logins.", user.getUsername());
                    auditService.logEvent(user.getId(), user.getUsername(), "ACCOUNT_LOCKED", ip, ua, "5 failed attempts. Locked for 15 minutes.");
                } else {
                    auditService.logEvent(user.getId(), user.getUsername(), "LOGIN_FAILURE", ip, ua, "Failed attempt " + attempts + "/5.");
                }
                userRepository.save(user);
                return;
            }
        }

        // Timing Attack Mitigation: Perform constant work even when user is missing or non-active
        passwordEncoder.matches("dummyPassword", "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");
        auditService.logEvent(null, username, "LOGIN_FAILURE", ip, ua, "Invalid credentials or inactive account.");
    }

    @Transactional
    public void handleLoginSuccess(String username, String ip, String ua) {
        Optional<AppUser> optUser = userRepository.findByUsernameOrEmail(username);
        if (optUser.isPresent()) {
            AppUser user = optUser.get();
            user.setFailedAttempts(0);
            user.setLockTime(null);
            userRepository.save(user);
            auditService.logEvent(user.getId(), user.getUsername(), "LOGIN_SUCCESS", ip, ua, "Login successful.");
        }
    }

    @Transactional(readOnly = true)
    public Page<AppUser> searchUsers(String query, UserStatus status, String roleName, Pageable pageable) {
        return userRepository.searchUsers(query, status, roleName, pageable);
    }

    @Transactional
    public void lockUser(Long userId, boolean locked, String adminUsername, String ip, String ua) {
        AppUser target = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng."));

        if (locked) {
            target.setStatus(UserStatus.LOCKED);
            target.setLockTime(LocalDateTime.now());
            auditService.logEvent(target.getId(), target.getUsername(), "ADMIN_LOCK", ip, ua, "Admin " + adminUsername + " locked user.");
        } else {
            target.setStatus(UserStatus.ACTIVE);
            target.setFailedAttempts(0);
            target.setLockTime(null);
            auditService.logEvent(target.getId(), target.getUsername(), "ADMIN_UNLOCK", ip, ua, "Admin " + adminUsername + " unlocked user.");
        }
        userRepository.save(target);
    }

    @Transactional
    public void disableUser(Long userId, String adminUsername, String ip, String ua) {
        AppUser target = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng."));

        // F10 Constraint: Luôn phải duy trì ít nhất 1 ADMIN ở trạng thái ACTIVE
        if (target.hasRole("ROLE_ADMIN")) {
            long activeAdminCount = userRepository.countByRoleNameAndStatus("ROLE_ADMIN", UserStatus.ACTIVE);
            if (activeAdminCount <= 1 && target.getStatus() == UserStatus.ACTIVE) {
                throw new IllegalStateException("Không thể vô hiệu hóa quản trị viên duy nhất đang hoạt động của hệ thống.");
            }
        }

        target.setStatus(UserStatus.DISABLED);
        target.setEnabled(false);
        userRepository.save(target);

        // Hủy tất cả phiên làm việc và remember-me token
        sessionManagementService.terminateAllSessions(target.getUsername());

        auditService.logEvent(target.getId(), target.getUsername(), "ADMIN_DISABLE", ip, ua, "Admin " + adminUsername + " disabled user and terminated sessions.");
    }

    @Transactional
    public void updateUserRoles(Long userId, Set<String> roleNames, String adminUsername, String ip, String ua) {
        AppUser target = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng."));

        // F10: Không thể gỡ vai trò ADMIN của admin duy nhất đang hoạt động
        if (target.hasRole("ROLE_ADMIN") && !roleNames.contains("ROLE_ADMIN")) {
            long activeAdminCount = userRepository.countByRoleNameAndStatus("ROLE_ADMIN", UserStatus.ACTIVE);
            if (activeAdminCount <= 1 && target.getStatus() == UserStatus.ACTIVE) {
                throw new IllegalStateException("Không thể gỡ vai trò ADMIN của quản trị viên duy nhất đang hoạt động.");
            }
        }

        Set<Role> updatedRoles = new HashSet<>();
        for (String roleName : roleNames) {
            Role role = roleRepository.findByName(roleName)
                    .orElseGet(() -> roleRepository.save(Role.builder().name(roleName).build()));
            updatedRoles.add(role);
        }

        target.setRoles(updatedRoles);
        userRepository.save(target);

        auditService.logEvent(target.getId(), target.getUsername(), "ROLE_CHANGED", ip, ua, "Admin " + adminUsername + " updated roles to: " + roleNames);
    }

    @Transactional
    public void deleteUser(Long userId, String adminUsername, String ip, String ua) {
        AppUser target = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy người dùng."));

        // F10 Constraint: Luôn phải duy trì ít nhất 1 ADMIN ở trạng thái ACTIVE
        if (target.hasRole("ROLE_ADMIN")) {
            long activeAdminCount = userRepository.countByRoleNameAndStatus("ROLE_ADMIN", UserStatus.ACTIVE);
            if (activeAdminCount <= 1 && target.getStatus() == UserStatus.ACTIVE) {
                throw new IllegalStateException("Không thể xóa quản trị viên duy nhất đang hoạt động của hệ thống.");
            }
        }

        sessionManagementService.terminateAllSessions(target.getUsername());
        userRepository.delete(target);
        auditService.logEvent(userId, target.getUsername(), "ADMIN_DELETE_USER", ip, ua, "Admin " + adminUsername + " deleted user.");
    }

    public Optional<AppUser> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<AppUser> findById(Long id) {
        return userRepository.findById(id);
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
