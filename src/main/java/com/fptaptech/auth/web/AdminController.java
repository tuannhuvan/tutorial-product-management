package com.fptaptech.auth.web;

import com.fptaptech.auth.audit.AuditLog;
import com.fptaptech.auth.audit.AuditLogRepository;
import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.CustomUserDetails;
import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.UserService;
import com.fptaptech.auth.user.UserStatus;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.*;

@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
@Slf4j
public class AdminController {

    private final UserService userService;
    private final AuditLogRepository auditLogRepository;

    public AdminController(UserService userService, AuditLogRepository auditLogRepository) {
        this.userService = userService;
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping("/users")
    public Object listUsers(
            @RequestParam(value = "query", required = false) String query,
            @RequestParam(value = "status", required = false) UserStatus status,
            @RequestParam(value = "roleName", required = false) String roleName,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "10") int size,
            @RequestHeader(value = "Accept", defaultValue = "text/html") String acceptHeader,
            Model model
    ) {
        Page<AppUser> usersPage = userService.searchUsers(
                query, status, roleName, PageRequest.of(page, size, Sort.by("createdAt").descending())
        );

        if (acceptHeader.contains("application/json")) {
            Map<String, Object> response = new HashMap<>();
            response.put("data", usersPage.getContent());
            Map<String, Object> pagination = new HashMap<>();
            pagination.put("total", usersPage.getTotalElements());
            pagination.put("count", usersPage.getNumberOfElements());
            pagination.put("per_page", usersPage.getSize());
            pagination.put("current_page", usersPage.getNumber() + 1);
            pagination.put("total_pages", usersPage.getTotalPages());
            response.put("pagination", pagination);
            return ResponseEntity.ok(response);
        }

        model.addAttribute("usersPage", usersPage);
        model.addAttribute("query", query);
        model.addAttribute("status", status);
        model.addAttribute("roleName", roleName);
        model.addAttribute("statuses", UserStatus.values());
        return "admin/users";
    }

    @PostMapping("/users/{id}/lock")
    public Object lockUser(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable("id") Long targetUserId,
            @RequestParam("locked") boolean locked,
            HttpServletRequest request,
            @RequestHeader(value = "Accept", defaultValue = "text/html") String acceptHeader,
            RedirectAttributes redirectAttributes
    ) {
        String ip = AuditService.getClientIp(request);
        String ua = AuditService.getUserAgent(request);

        try {
            userService.lockUser(targetUserId, locked, userDetails.getUsername(), ip, ua);
            if (acceptHeader.contains("application/json")) {
                return ResponseEntity.ok(Collections.singletonMap("message", locked ? "User locked" : "User unlocked"));
            }
            redirectAttributes.addFlashAttribute("successMessage", locked ? "Đã khóa tài khoản thành công." : "Đã mở khóa tài khoản thành công.");
        } catch (Exception e) {
            if (acceptHeader.contains("application/json")) {
                return ResponseEntity.badRequest().body(Collections.singletonMap("error", e.getMessage()));
            }
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/disable")
    public Object disableUser(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable("id") Long targetUserId,
            HttpServletRequest request,
            @RequestHeader(value = "Accept", defaultValue = "text/html") String acceptHeader,
            RedirectAttributes redirectAttributes
    ) {
        String ip = AuditService.getClientIp(request);
        String ua = AuditService.getUserAgent(request);

        try {
            userService.disableUser(targetUserId, userDetails.getUsername(), ip, ua);
            if (acceptHeader.contains("application/json")) {
                return ResponseEntity.ok(Collections.singletonMap("message", "User disabled and sessions terminated"));
            }
            redirectAttributes.addFlashAttribute("successMessage", "Đã vô hiệu hóa tài khoản và hủy toàn bộ các phiên làm việc.");
        } catch (Exception e) {
            if (acceptHeader.contains("application/json")) {
                return ResponseEntity.badRequest().body(Collections.singletonMap("error", e.getMessage()));
            }
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/roles")
    public String updateRoles(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable("id") Long targetUserId,
            @RequestParam("roles") List<String> roles,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        String ip = AuditService.getClientIp(request);
        String ua = AuditService.getUserAgent(request);

        try {
            userService.updateUserRoles(targetUserId, new HashSet<>(roles), userDetails.getUsername(), ip, ua);
            redirectAttributes.addFlashAttribute("successMessage", "Cập nhật vai trò người dùng thành công.");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{id}/delete")
    public Object deleteUser(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @PathVariable("id") Long targetUserId,
            HttpServletRequest request,
            @RequestHeader(value = "Accept", defaultValue = "text/html") String acceptHeader,
            RedirectAttributes redirectAttributes
    ) {
        String ip = AuditService.getClientIp(request);
        String ua = AuditService.getUserAgent(request);

        try {
            userService.deleteUser(targetUserId, userDetails.getUsername(), ip, ua);
            if (acceptHeader.contains("application/json")) {
                return ResponseEntity.ok(Collections.singletonMap("message", "User deleted successfully"));
            }
            redirectAttributes.addFlashAttribute("successMessage", "Đã xóa tài khoản người dùng thành công.");
        } catch (Exception e) {
            if (acceptHeader.contains("application/json")) {
                return ResponseEntity.badRequest().body(Collections.singletonMap("error", e.getMessage()));
            }
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/users";
    }

    @GetMapping("/audit-logs")
    public Object listAuditLogs(
            @RequestParam(value = "eventType", required = false) String eventType,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "ipAddress", required = false) String ipAddress,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "20") int size,
            @RequestHeader(value = "Accept", defaultValue = "text/html") String acceptHeader,
            Model model
    ) {
        Page<AuditLog> logsPage = auditLogRepository.searchLogs(
                eventType, username, ipAddress, null, null,
                PageRequest.of(page, size)
        );

        if (acceptHeader.contains("application/json")) {
            Map<String, Object> response = new HashMap<>();
            response.put("data", logsPage.getContent());
            Map<String, Object> pagination = new HashMap<>();
            pagination.put("total", logsPage.getTotalElements());
            pagination.put("count", logsPage.getNumberOfElements());
            pagination.put("per_page", logsPage.getSize());
            pagination.put("current_page", logsPage.getNumber() + 1);
            pagination.put("total_pages", logsPage.getTotalPages());
            response.put("pagination", pagination);
            return ResponseEntity.ok(response);
        }

        model.addAttribute("logsPage", logsPage);
        model.addAttribute("eventType", eventType);
        model.addAttribute("username", username);
        model.addAttribute("ipAddress", ipAddress);
        return "admin/audit-logs";
    }
}
