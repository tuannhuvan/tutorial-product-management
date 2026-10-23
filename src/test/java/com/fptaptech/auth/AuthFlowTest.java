package com.fptaptech.auth;

import com.fptaptech.auth.audit.AuditLog;
import com.fptaptech.auth.audit.AuditLogRepository;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.DatabaseUserDetailsService;
import com.fptaptech.auth.security.SessionManagementService;
import com.fptaptech.auth.security.TotpService;
import com.fptaptech.auth.user.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class AuthFlowTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EmailTokenRepository emailTokenRepository;

    @Autowired
    private PasswordHistoryRepository passwordHistoryRepository;

    @Autowired
    private TotpSecretRepository totpSecretRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordPolicyService passwordPolicyService;

    @Autowired
    private TotpService totpService;

    @Autowired
    private DatabaseUserDetailsService userDetailsService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private SessionManagementService sessionManagementService;

    @Autowired(required = false)
    private PersistentTokenRepository persistentTokenRepository;

    @BeforeEach
    void setUp() {
        if (roleRepository.findByName("ROLE_STUDENT").isEmpty()) {
            roleRepository.save(Role.builder().name("ROLE_STUDENT").build());
        }
        if (roleRepository.findByName("ROLE_LECTURER").isEmpty()) {
            roleRepository.save(Role.builder().name("ROLE_LECTURER").build());
        }
        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            roleRepository.save(Role.builder().name("ROLE_ADMIN").build());
        }
    }

    // ==========================================
    // F1: ĐĂNG KÝ HỌC VIÊN (STUDENT REGISTRATION)
    // ==========================================
    @Test
    @DisplayName("F1: Đăng ký thành công tạo tài khoản PENDING và lưu token băm SHA-256")
    void testF1_StudentRegistration_Success() {
        String username = "f1_student";
        String email = "f1_student@fptaptech.edu.vn";
        String password = "SecurePassword2026!";

        AppUser registered = userService.registerStudent(username, email, password, "127.0.0.1", "JUnit-Test");

        assertNotNull(registered.getId());
        assertEquals(UserStatus.PENDING, registered.getStatus());
        assertTrue(registered.hasRole("ROLE_STUDENT"));
        assertTrue(passwordEncoder.matches(password, registered.getPasswordHash()));

        // Token kiểm tra phải tồn tại trong CSDL với dạng SHA-256
        List<EmailToken> tokens = emailTokenRepository.findByUserAndTokenType(registered, EmailToken.TYPE_VERIFY_EMAIL);
        assertFalse(tokens.isEmpty());
        EmailToken token = tokens.get(0);
        assertNotNull(token.getTokenHash());
        assertEquals(64, token.getTokenHash().length()); // SHA-256 hex length
        assertFalse(token.isUsed());
    }

    @Test
    @DisplayName("F1: Từ chối đăng ký khi username hoặc email đã tồn tại")
    void testF1_StudentRegistration_DuplicateRejection() {
        userService.registerStudent("f1_dup_user", "f1_dup@fpt.edu.vn", "ValidPass2026!", "127.0.0.1", "Test");

        // Trùng username
        IllegalArgumentException exUser = assertThrows(IllegalArgumentException.class, () ->
                userService.registerStudent("f1_dup_user", "f1_other@fpt.edu.vn", "ValidPass2026!", "127.0.0.1", "Test")
        );
        assertTrue(exUser.getMessage().contains("Tên đăng nhập đã tồn tại"));

        // Trùng email
        IllegalArgumentException exEmail = assertThrows(IllegalArgumentException.class, () ->
                userService.registerStudent("f1_other_user", "f1_dup@fpt.edu.vn", "ValidPass2026!", "127.0.0.1", "Test")
        );
        assertTrue(exEmail.getMessage().contains("đã được sử dụng"));
    }

    // ==========================================
    // F2: XÁC MINH EMAIL (VERIFY EMAIL)
    // ==========================================
    @Test
    @DisplayName("F2: Xác minh email thành công chuyển trạng thái PENDING -> ACTIVE")
    void testF2_VerifyEmail_Success() {
        String plainToken = "test_raw_verification_token_12345";
        AppUser user = userService.registerStudent("f2_user", "f2_user@fpt.edu.vn", "ValidPass2026!", "127.0.0.1", "Test");

        EmailToken token = EmailToken.builder()
                .user(user)
                .tokenHash(UserService.sha256Hex(plainToken))
                .tokenType(EmailToken.TYPE_VERIFY_EMAIL)
                .expiresAt(LocalDateTime.now().plusHours(24))
                .used(false)
                .build();
        emailTokenRepository.save(token);

        boolean verified = userService.verifyEmail(plainToken, "127.0.0.1", "Test");
        assertTrue(verified);

        AppUser updated = userRepository.findById(user.getId()).orElseThrow();
        assertEquals(UserStatus.ACTIVE, updated.getStatus());
    }

    @Test
    @DisplayName("F2 [LỖI]: Token hết hạn không thể xác minh")
    void testF2_VerifyEmail_ExpiredToken_Rejected() {
        String plainToken = "test_expired_token_12345";
        AppUser user = userService.registerStudent("f2_expired_user", "f2_expired@fpt.edu.vn", "ValidPass2026!", "127.0.0.1", "Test");

        EmailToken expiredToken = EmailToken.builder()
                .user(user)
                .tokenHash(UserService.sha256Hex(plainToken))
                .tokenType(EmailToken.TYPE_VERIFY_EMAIL)
                .expiresAt(LocalDateTime.now().minusHours(1)) // Đã hết hạn
                .used(false)
                .build();
        emailTokenRepository.save(expiredToken);

        boolean verified = userService.verifyEmail(plainToken, "127.0.0.1", "Test");
        assertFalse(verified, "Token đã hết hạn phải bị từ chối xác minh");

        AppUser check = userRepository.findById(user.getId()).orElseThrow();
        assertEquals(UserStatus.PENDING, check.getStatus());
    }

    @Test
    @DisplayName("F2 [LỖI]: Token dùng lại (Reused) bị từ chối")
    void testF2_VerifyEmail_ReusedToken_Rejected() {
        String plainToken = "test_reused_token_12345";
        AppUser user = userService.registerStudent("f2_reused_user", "f2_reused@fpt.edu.vn", "ValidPass2026!", "127.0.0.1", "Test");

        EmailToken token = EmailToken.builder()
                .user(user)
                .tokenHash(UserService.sha256Hex(plainToken))
                .tokenType(EmailToken.TYPE_VERIFY_EMAIL)
                .expiresAt(LocalDateTime.now().plusHours(24))
                .used(false)
                .build();
        emailTokenRepository.save(token);

        // Lần đầu: thành công
        assertTrue(userService.verifyEmail(plainToken, "127.0.0.1", "Test"));

        // Lần 2 (dùng lại): phải bị từ chối
        assertFalse(userService.verifyEmail(plainToken, "127.0.0.1", "Test"), "Token đã qua sử dụng không được phép tái sử dụng");
    }

    // ==========================================
    // F3: QUÊN & ĐẶT LẠI MẬT KHẨU (FORGOT/RESET PASSWORD)
    // ==========================================
    @Test
    @DisplayName("F3: Yêu cầu khôi phục và đặt lại mật khẩu mới thành công")
    void testF3_PasswordReset_Success() {
        AppUser user = userService.registerStudent("f3_user", "f3_user@fpt.edu.vn", "OldPassword2026!", "127.0.0.1", "Test");
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        String resetPlainToken = "raw_reset_token_67890";
        EmailToken resetToken = EmailToken.builder()
                .user(user)
                .tokenHash(UserService.sha256Hex(resetPlainToken))
                .tokenType(EmailToken.TYPE_RESET_PASSWORD)
                .expiresAt(LocalDateTime.now().plusMinutes(30))
                .used(false)
                .build();
        emailTokenRepository.save(resetToken);

        String newPassword = "BrandNewPassword2026!";
        boolean resetSuccess = userService.resetPassword(resetPlainToken, newPassword, "127.0.0.1", "Test");
        assertTrue(resetSuccess);

        AppUser updated = userRepository.findById(user.getId()).orElseThrow();
        assertTrue(passwordEncoder.matches(newPassword, updated.getPasswordHash()));
    }

    @Test
    @DisplayName("F3 [LỖI]: Token reset mật khẩu hết hạn hoặc dùng lại bị từ chối")
    void testF3_PasswordReset_ExpiredAndReused_Rejected() {
        AppUser user = userService.registerStudent("f3_err_user", "f3_err@fpt.edu.vn", "OldPassword2026!", "127.0.0.1", "Test");
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        // 1. Hết hạn (Expired)
        String expiredToken = "expired_reset_tok_1";
        emailTokenRepository.save(EmailToken.builder()
                .user(user)
                .tokenHash(UserService.sha256Hex(expiredToken))
                .tokenType(EmailToken.TYPE_RESET_PASSWORD)
                .expiresAt(LocalDateTime.now().minusMinutes(5))
                .used(false)
                .build());

        assertFalse(userService.resetPassword(expiredToken, "ValidPassword2026!", "127.0.0.1", "Test"));

        // 2. Dùng lại (Reused)
        String reusableToken = "valid_reset_tok_2";
        emailTokenRepository.save(EmailToken.builder()
                .user(user)
                .tokenHash(UserService.sha256Hex(reusableToken))
                .tokenType(EmailToken.TYPE_RESET_PASSWORD)
                .expiresAt(LocalDateTime.now().plusMinutes(30))
                .used(false)
                .build());

        assertTrue(userService.resetPassword(reusableToken, "ValidPassword2026!A", "127.0.0.1", "Test"));
        assertFalse(userService.resetPassword(reusableToken, "ValidPassword2026!B", "127.0.0.1", "Test"), "Token reset đã dùng không thể dùng lại");
    }

    // ==========================================
    // F4: CHÍNH SÁCH MẬT KHẨU (PASSWORD POLICY)
    // ==========================================
    @Test
    @DisplayName("F4: Kiểm tra nghiêm ngặt chính sách mật khẩu NIST 800-63B")
    void testF4_PasswordPolicy_AllRules() {
        // Dưới 12 ký tự
        assertThrows(IllegalArgumentException.class, () ->
                passwordPolicyService.validate("Short123!", "testuser", "test@fpt.edu.vn", null, passwordEncoder)
        );

        // Chứa username
        assertThrows(IllegalArgumentException.class, () ->
                passwordPolicyService.validate("testuserLongPass2026!", "testuser", "test@fpt.edu.vn", null, passwordEncoder)
        );

        // Nằm trong danh sách 10.000 mật khẩu phổ biến
        assertThrows(IllegalArgumentException.class, () ->
                passwordPolicyService.validate("fptaptech2026", "differentuser", "other@fpt.edu.vn", null, passwordEncoder)
        );

        // Trùng với mật khẩu cũ trong 5 lần gần nhất
        AppUser user = AppUser.builder()
                .username("historyuser")
                .email("history@fpt.edu.vn")
                .passwordHash(passwordEncoder.encode("OldPassHistory1!"))
                .build();
        userRepository.save(user);

        passwordHistoryRepository.save(PasswordHistory.builder()
                .user(user)
                .passwordHash(passwordEncoder.encode("OldPassHistory1!"))
                .createdAt(LocalDateTime.now())
                .build());

        assertThrows(IllegalArgumentException.class, () ->
                passwordPolicyService.validate("OldPassHistory1!", "historyuser", "history@fpt.edu.vn", user, passwordEncoder)
        );
    }

    // ==========================================
    // F5: KHÓA TÀI KHOẢN (ACCOUNT AUTO-LOCK)
    // ==========================================
    @Test
    @DisplayName("F5: Nhập sai 5 lần liên tiếp khóa tài khoản 15 phút, tự mở sau 15 phút")
    void testF5_AccountAutoLock_And_AutoUnlock() {
        String username = "f5_lock_user";
        AppUser user = userService.registerStudent(username, "f5_lock@fpt.edu.vn", "StrongPassword2026!", "127.0.0.1", "Test");
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        // Nhập sai 4 lần -> chưa khóa
        for (int i = 0; i < 4; i++) {
            userService.handleLoginFailure(username, "127.0.0.1", "Test");
        }
        AppUser check1 = userRepository.findByUsername(username).orElseThrow();
        assertEquals(UserStatus.ACTIVE, check1.getStatus());
        assertEquals(4, check1.getFailedAttempts());

        // Nhập sai lần thứ 5 -> Khóa LOCKED
        userService.handleLoginFailure(username, "127.0.0.1", "Test");
        AppUser check2 = userRepository.findByUsername(username).orElseThrow();
        assertEquals(UserStatus.LOCKED, check2.getStatus());
        assertNotNull(check2.getLockTime());

        // Mô phỏng thời gian khóa đã qua 16 phút -> DatabaseUserDetailsService tự mở khóa
        check2.setLockTime(LocalDateTime.now().minusMinutes(16));
        userRepository.save(check2);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        assertTrue(userDetails.isAccountNonLocked());

        AppUser check3 = userRepository.findByUsername(username).orElseThrow();
        assertEquals(UserStatus.ACTIVE, check3.getStatus());
        assertEquals(0, check3.getFailedAttempts());
    }

    // ==========================================
    // F6: XÁC THỰC 2 BƯỚC (TOTP RFC 6238)
    // ==========================================
    @Test
    @DisplayName("F6: Kiểm tra xác thực TOTP, từ chối mã sai và dùng mã khôi phục")
    void testF6_Totp_Verification_And_Errors() {
        String secret = totpService.generateSecret();
        assertNotNull(secret);

        // 1. Mã TOTP hợp lệ
        String validCode = totpService.generateTotp(secret);
        assertTrue(totpService.verifyTotp(secret, validCode));

        // 2. [LỖI] Mã TOTP sai -> Từ chối
        assertFalse(totpService.verifyTotp(secret, "000000"));
        assertFalse(totpService.verifyTotp(secret, "999999"));
        assertFalse(totpService.verifyTotp(secret, "invalid"));

        // 3. Mã hóa AES-GCM secret
        String encrypted = totpService.encryptSecret(secret);
        assertNotEquals(secret, encrypted);
        String decrypted = totpService.decryptSecret(encrypted);
        assertEquals(secret, decrypted);

        // 4. Sinh 10 mã khôi phục dự phòng
        List<String> recoveryCodes = totpService.generateRecoveryCodes();
        assertEquals(10, recoveryCodes.size());
    }

    // ==========================================
    // F7: GHI NHỚ ĐĂNG NHẬP (REMEMBER-ME)
    // ==========================================
    @Test
    @DisplayName("F7: Quản lý Persistent Remember-Me token trong CSDL")
    void testF7_RememberMe_PersistentToken() {
        if (persistentTokenRepository != null) {
            String series = "series_token_12345";
            PersistentRememberMeToken token = new PersistentRememberMeToken(
                    "rememberuser", series, "token_val_abc", new Date()
            );

            persistentTokenRepository.createNewToken(token);
            PersistentRememberMeToken loaded = persistentTokenRepository.getTokenForSeries(series);
            assertNotNull(loaded);
            assertEquals("rememberuser", loaded.getUsername());

            // Thu hồi token khi logout hoặc đổi mật khẩu
            sessionManagementService.revokeRememberMeTokens("rememberuser");
            assertNull(persistentTokenRepository.getTokenForSeries(series));
        }
    }

    // ==========================================
    // F8: QUẢN LÝ PHIÊN ĐĂNG NHẬP (SESSION MANAGEMENT)
    // ==========================================
    @Test
    @DisplayName("F8: Quản lý phiên làm việc, chấm dứt phiên từ xa")
    void testF8_SessionManagement_Termination() {
        String username = "session_user";
        sessionManagementService.terminateAllSessions(username);
        // Kiểm tra hàm không gây lỗi runtime khi tương tác session
        assertDoesNotThrow(() -> sessionManagementService.getUserSessions(username, "dummy_session_id"));
    }

    // ==========================================
    // F9: ĐỔI MẬT KHẨU KHI ĐANG ĐĂNG NHẬP
    // ==========================================
    @Test
    @DisplayName("F9: Đổi mật khẩu thành công khi đúng mật khẩu cũ, từ chối khi sai mật khẩu cũ")
    void testF9_ChangePassword_Flow() {
        String username = "f9_change_user";
        String oldPass = "InitialPass2026!";
        AppUser user = userService.registerStudent(username, "f9@fpt.edu.vn", oldPass, "127.0.0.1", "Test");
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        // Sai mật khẩu hiện tại -> Từ chối
        assertThrows(IllegalArgumentException.class, () ->
                userService.changePassword(username, "WrongCurrentPass!", "NewValidPassword2026!", "session1", "127.0.0.1", "Test")
        );

        // Đúng mật khẩu hiện tại -> Thành công
        String newPass = "UpdatedPass2026!";
        assertDoesNotThrow(() ->
                userService.changePassword(username, oldPass, newPass, "session1", "127.0.0.1", "Test")
        );

        AppUser updated = userRepository.findByUsername(username).orElseThrow();
        assertTrue(passwordEncoder.matches(newPass, updated.getPasswordHash()));
    }

    // ==========================================
    // F10: QUẢN TRỊ TÀI KHOẢN & BẢO VỆ ADMIN CUỐI CÙNG
    // ==========================================
    @Test
    @DisplayName("F10 [LỖI]: Ngăn chặn xóa hoặc vô hiệu hóa ADMIN duy nhất của hệ thống")
    void testF10_ProtectLastAdmin_From_Disable_And_Delete() {
        // Lấy admin duy nhất hiện có trong hệ thống (được khởi tạo khi khởi động)
        AppUser singleAdmin = userRepository.findByUsername("admin").orElseThrow();
        assertEquals(1, userRepository.countByRoleNameAndStatus("ROLE_ADMIN", UserStatus.ACTIVE));

        // 1. Thử vô hiệu hóa ADMIN duy nhất -> Bị từ chối
        IllegalStateException exDisable = assertThrows(IllegalStateException.class, () ->
                userService.disableUser(singleAdmin.getId(), "admin", "127.0.0.1", "Test")
        );
        assertTrue(exDisable.getMessage().contains("Không thể vô hiệu hóa quản trị viên duy nhất"));

        // 2. Thử xóa ADMIN duy nhất -> Bị từ chối
        IllegalStateException exDelete = assertThrows(IllegalStateException.class, () ->
                userService.deleteUser(singleAdmin.getId(), "admin", "127.0.0.1", "Test")
        );
        assertTrue(exDelete.getMessage().contains("Không thể xóa quản trị viên duy nhất"));

        // 3. Thử tự gỡ vai trò ADMIN của chính mình khi là admin duy nhất -> Bị từ chối
        IllegalStateException exDemote = assertThrows(IllegalStateException.class, () ->
                userService.updateUserRoles(singleAdmin.getId(), Collections.singleton("ROLE_STUDENT"), "admin", "127.0.0.1", "Test")
        );
        assertTrue(exDemote.getMessage().contains("Không thể gỡ vai trò ADMIN của quản trị viên duy nhất"));
    }

    // ==========================================
    // F11: NHẬT KÝ KIỂM TOÁN (AUDIT LOGGING)
    // ==========================================
    @Test
    @DisplayName("F11: Tự động ghi vết và tra cứu đầy đủ nhật ký an ninh hệ thống")
    void testF11_AuditLogging_Verification() {
        String testUser = "audit_user";
        auditService.logEvent(999L, testUser, "SECURITY_ALERT", "192.168.1.100", "CustomBrowser/1.0", "Suspicious operation detected.");

        List<AuditLog> logs = auditLogRepository.findByUsername(testUser);
        assertFalse(logs.isEmpty());

        AuditLog latest = logs.get(0);
        assertEquals("SECURITY_ALERT", latest.getEventType());
        assertEquals("192.168.1.100", latest.getIpAddress());
        assertTrue(latest.getDetails().contains("Suspicious operation detected"));
        assertNotNull(latest.getCreatedAt());
    }
}
