package com.fptaptech.auth.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class PasswordPolicyService {

    private final PasswordHistoryRepository passwordHistoryRepository;

    public PasswordPolicyService(PasswordHistoryRepository passwordHistoryRepository) {
        this.passwordHistoryRepository = passwordHistoryRepository;
    }

    // Common passwords list based on top leaked/weak passwords
    private static final Set<String> COMMON_PASSWORDS = new HashSet<>(Arrays.asList(
            "123456789012", "password1234", "password12345", "admin1234567",
            "qwertyuiop12", "welcome12345", "administrator", "iloveyou1234",
            "monkey123456", "dragon123456", "sunshine1234", "princess1234",
            "football1234", "baseball1234", "superman1234", "trustno11234",
            "fptaptech123", "fptaptech2026", "aptech123456", "fpt123456789"
    ));

    public void validate(String password, String username, String email, AppUser existingUser, PasswordEncoder passwordEncoder) {
        if (password == null || password.length() < 12) {
            throw new IllegalArgumentException("Mật khẩu phải chứa ít nhất 12 ký tự.");
        }

        String lowerPassword = password.toLowerCase();

        // 1. Không chứa username
        if (username != null && !username.isBlank()) {
            if (lowerPassword.contains(username.toLowerCase())) {
                throw new IllegalArgumentException("Mật khẩu không được chứa tên đăng nhập.");
            }
        }

        // 2. Không chứa phần tên của email
        if (email != null && email.contains("@")) {
            String emailPrefix = email.split("@")[0].toLowerCase();
            if (emailPrefix.length() >= 3 && lowerPassword.contains(emailPrefix)) {
                throw new IllegalArgumentException("Mật khẩu không được chứa phần tên của email.");
            }
        }

        // 3. Không nằm trong danh sách mật khẩu phổ biến
        if (COMMON_PASSWORDS.contains(lowerPassword)) {
            throw new IllegalArgumentException("Mật khẩu này quá phổ biến và dễ đoán. Vui lòng chọn mật khẩu phức tạp hơn.");
        }

        // 4. Không trùng với 5 mật khẩu gần nhất
        if (existingUser != null && passwordEncoder != null) {
            List<PasswordHistory> histories = passwordHistoryRepository.findTop5ByUserOrderByCreatedAtDesc(existingUser);
            for (PasswordHistory history : histories) {
                if (passwordEncoder.matches(password, history.getPasswordHash())) {
                    throw new IllegalArgumentException("Mật khẩu mới không được trùng với 5 mật khẩu gần nhất đã sử dụng.");
                }
            }
        }
    }
}
