package com.fptaptech.auth.web;

import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@Slf4j
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            @RequestParam(value = "registered", required = false) String registered,
            @RequestParam(value = "verified", required = false) String verified,
            @RequestParam(value = "verifyError", required = false) String verifyError,
            @RequestParam(value = "resetSuccess", required = false) String resetSuccess,
            @RequestParam(value = "resendSent", required = false) String resendSent,
            Model model
    ) {
        if (error != null) {
            model.addAttribute("errorMessage", "Tài khoản hoặc mật khẩu không chính xác hoặc chưa được kích hoạt.");
        }
        if (logout != null) {
            model.addAttribute("successMessage", "Bạn đã đăng xuất an toàn khỏi hệ thống.");
        }
        if (registered != null) {
            model.addAttribute("infoMessage", "Đăng ký thành công! Một email xác minh đã được gửi đến hòm thư của bạn. Vui lòng kiểm tra và kích hoạt tài khoản trong vòng 24 giờ.");
        }
        if (verified != null) {
            model.addAttribute("successMessage", "Xác minh tài khoản thành công! Bạn có thể đăng nhập ngay bây giờ.");
        }
        if (verifyError != null) {
            model.addAttribute("errorMessage", "Liên kết xác minh không hợp lệ hoặc đã hết hạn (24 giờ). Vui lòng thử gửi lại email xác minh.");
        }
        if (resetSuccess != null) {
            model.addAttribute("successMessage", "Mật khẩu của bạn đã được thay đổi thành công. Vui lòng đăng nhập với mật khẩu mới.");
        }
        if (resendSent != null) {
            model.addAttribute("infoMessage", "Nếu email chưa kích hoạt, liên kết xác minh mới đã được gửi vào hòm thư.");
        }
        return "login";
    }

    @GetMapping("/registration")
    public String registration(Model model) {
        if (!model.containsAttribute("registrationForm")) {
            model.addAttribute("registrationForm", new RegistrationForm());
        }
        return "registration";
    }

    @PostMapping("/registration")
    public String handleRegistration(
            @Valid @ModelAttribute("registrationForm") RegistrationForm form,
            BindingResult bindingResult,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            return "registration";
        }

        try {
            String ip = AuditService.getClientIp(request);
            String ua = AuditService.getUserAgent(request);
            userService.registerStudent(form.getUsername(), form.getEmail(), form.getPassword(), ip, ua);
            redirectAttributes.addAttribute("registered", "true");
            return "redirect:/login";
        } catch (IllegalArgumentException | IllegalStateException e) {
            bindingResult.reject("registrationError", e.getMessage());
            return "registration";
        }
    }

    @GetMapping("/verify-email")
    public String verifyEmail(
            @RequestParam("token") String token,
            HttpServletRequest request
    ) {
        String ip = AuditService.getClientIp(request);
        String ua = AuditService.getUserAgent(request);
        boolean success = userService.verifyEmail(token, ip, ua);
        if (success) {
            return "redirect:/login?verified=true";
        } else {
            return "redirect:/login?verifyError=true";
        }
    }

    @PostMapping("/resend-verification")
    public String resendVerification(
            @RequestParam("email") String email,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        try {
            String ip = AuditService.getClientIp(request);
            String ua = AuditService.getUserAgent(request);
            userService.resendVerificationEmail(email, ip, ua);
            redirectAttributes.addAttribute("resendSent", "true");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/login";
    }

    @GetMapping("/forgot-password")
    public String forgotPassword(
            @RequestParam(value = "sent", required = false) String sent,
            Model model
    ) {
        if (sent != null) {
            model.addAttribute("infoMessage", "Nếu email tồn tại trong hệ thống, liên kết khôi phục đã được gửi vào hòm thư (hiệu lực trong 30 phút).");
        }
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String handleForgotPassword(
            @RequestParam("email") String email,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        String ip = AuditService.getClientIp(request);
        String ua = AuditService.getUserAgent(request);
        userService.requestPasswordReset(email, ip, ua);
        redirectAttributes.addAttribute("sent", "true");
        return "redirect:/forgot-password";
    }

    @GetMapping("/reset-password")
    public String resetPasswordPage(
            @RequestParam("token") String token,
            @RequestParam(value = "error", required = false) String error,
            Model model
    ) {
        model.addAttribute("token", token);
        if (error != null) {
            model.addAttribute("errorMessage", "Không thể đặt lại mật khẩu. Liên kết không hợp lệ, đã hết hạn hoặc mật khẩu không đáp ứng chính sách bảo mật.");
        }
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String handleResetPassword(
            @RequestParam("token") String token,
            @RequestParam("newPassword") String newPassword,
            @RequestParam("confirmPassword") String confirmPassword,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes,
            Model model
    ) {
        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("token", token);
            model.addAttribute("errorMessage", "Mật khẩu xác nhận không khớp.");
            return "reset-password";
        }

        try {
            String ip = AuditService.getClientIp(request);
            String ua = AuditService.getUserAgent(request);
            boolean success = userService.resetPassword(token, newPassword, ip, ua);
            if (success) {
                redirectAttributes.addAttribute("resetSuccess", "true");
                return "redirect:/login";
            } else {
                model.addAttribute("token", token);
                model.addAttribute("errorMessage", "Liên kết khôi phục không hợp lệ hoặc đã hết hạn.");
                return "reset-password";
            }
        } catch (IllegalArgumentException e) {
            model.addAttribute("token", token);
            model.addAttribute("errorMessage", e.getMessage());
            return "reset-password";
        }
    }
}
