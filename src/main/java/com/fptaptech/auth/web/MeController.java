package com.fptaptech.auth.web;

import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.CustomUserDetails;
import com.fptaptech.auth.security.SessionManagementService;
import com.fptaptech.auth.security.UserSessionDto;
import com.fptaptech.auth.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/me")
@Slf4j
public class MeController {

    private final SessionManagementService sessionManagementService;
    private final UserService userService;

    public MeController(SessionManagementService sessionManagementService, UserService userService) {
        this.sessionManagementService = sessionManagementService;
        this.userService = userService;
    }

    @GetMapping("/sessions")
    public Object listSessions(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            HttpSession session,
            @RequestHeader(value = "Accept", defaultValue = "text/html") String acceptHeader,
            Model model
    ) {
        if (userDetails == null) return "redirect:/login";

        String currentSessionId = session != null ? session.getId() : "";
        List<UserSessionDto> sessions = sessionManagementService.getUserSessions(userDetails.getUsername(), currentSessionId);

        if (acceptHeader.contains("application/json")) {
            return ResponseEntity.ok(Collections.singletonMap("data", sessions));
        }

        model.addAttribute("sessions", sessions);
        return "sessions";
    }

    @PostMapping("/sessions/{id}/terminate")
    public String terminateSession(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable("id") String sessionId,
            RedirectAttributes redirectAttributes
    ) {
        if (userDetails == null) return "redirect:/login";
        sessionManagementService.terminateSession(userDetails.getUsername(), sessionId);
        redirectAttributes.addFlashAttribute("successMessage", "Đã đăng xuất phiên làm việc thành công.");
        return "redirect:/me/sessions";
    }

    @DeleteMapping("/sessions/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteSession(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable("id") String sessionId
    ) {
        if (userDetails == null) return ResponseEntity.status(401).build();
        sessionManagementService.terminateSession(userDetails.getUsername(), sessionId);
        return ResponseEntity.ok(Collections.singletonMap("message", "Session terminated."));
    }

    @GetMapping("/change-password")
    public String changePasswordPage(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            Model model
    ) {
        if (userDetails == null) return "redirect:/login";
        return "change-password";
    }

    @PostMapping("/change-password")
    public String handleChangePassword(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam("currentPassword") String currentPassword,
            @RequestParam("newPassword") String newPassword,
            @RequestParam("confirmPassword") String confirmPassword,
            HttpSession session,
            HttpServletRequest request,
            Model model,
            RedirectAttributes redirectAttributes
    ) {
        if (userDetails == null) return "redirect:/login";

        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("errorMessage", "Mật khẩu xác nhận không khớp.");
            return "change-password";
        }

        try {
            String ip = AuditService.getClientIp(request);
            String ua = AuditService.getUserAgent(request);
            String currentSessionId = session != null ? session.getId() : "";

            userService.changePassword(userDetails.getUsername(), currentPassword, newPassword, currentSessionId, ip, ua);
            redirectAttributes.addFlashAttribute("successMessage", "Mật khẩu đã được thay đổi thành công. Tất cả các phiên đăng nhập khác đã được thu hồi.");
            return "redirect:/";
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", e.getMessage());
            return "change-password";
        }
    }
}
