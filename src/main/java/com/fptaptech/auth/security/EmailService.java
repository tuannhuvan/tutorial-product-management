package com.fptaptech.auth.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    public void sendVerificationEmail(String toEmail, String plainToken) {
        String verificationUrl = baseUrl + "/verify-email?token=" + plainToken;
        String subject = "[FPT Aptech Portal] Xác minh địa chỉ email của bạn";
        String content = "Chào bạn,\n\n"
                + "Cảm ơn bạn đã đăng ký tài khoản tại Cổng thông tin học viên FPT Aptech.\n"
                + "Vui lòng nhấp vào liên kết sau để kích hoạt tài khoản của bạn (liên kết có hiệu lực trong 24 giờ):\n"
                + verificationUrl + "\n\n"
                + "Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email này.\n\n"
                + "Trân trọng,\nBan quản trị FPT Aptech";

        sendEmail(toEmail, subject, content, verificationUrl);
    }

    public void sendPasswordResetEmail(String toEmail, String plainToken) {
        String resetUrl = baseUrl + "/reset-password?token=" + plainToken;
        String subject = "[FPT Aptech Portal] Yêu cầu khôi phục mật khẩu";
        String content = "Chào bạn,\n\n"
                + "Chúng tôi nhận được yêu cầu khôi phục mật khẩu cho tài khoản liên kết với email này.\n"
                + "Vui lòng nhấp vào liên kết sau để đặt lại mật khẩu mới (liên kết có hiệu lực trong 30 phút):\n"
                + resetUrl + "\n\n"
                + "Nếu bạn không yêu cầu điều này, tài khoản của bạn vẫn an toàn và bạn có thể bỏ qua email này.\n\n"
                + "Trân trọng,\nBan quản trị FPT Aptech";

        sendEmail(toEmail, subject, content, resetUrl);
    }

    private void sendEmail(String toEmail, String subject, String content, String actionUrl) {
        log.info("===============================================================================");
        log.info("EMAIL DISPATCHED TO: {}", toEmail);
        log.info("SUBJECT: {}", subject);
        log.info("ACTION LINK: {}", actionUrl);
        log.info("===============================================================================");

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("no-reply@fptaptech.edu.vn");
            message.setTo(toEmail);
            message.setSubject(subject);
            message.setText(content);
            mailSender.send(message);
            log.info("Email successfully sent via SMTP to {}", toEmail);
        } catch (Exception e) {
            log.warn("SMTP host not available or failed: {}. Link is logged above for testing.", e.getMessage());
        }
    }
}
