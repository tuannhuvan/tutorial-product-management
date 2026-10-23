package com.fptaptech.auth.web;

import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.CustomUserDetails;
import com.fptaptech.auth.security.TotpService;
import com.fptaptech.auth.user.AppUser;
import com.fptaptech.auth.user.TotpSecret;
import com.fptaptech.auth.user.TotpSecretRepository;
import com.fptaptech.auth.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.*;

@Controller
@RequestMapping("/totp")
@Slf4j
public class TotpController {

    private final TotpService totpService;
    private final TotpSecretRepository totpSecretRepository;
    private final UserService userService;
    private final AuditService auditService;

    public TotpController(TotpService totpService,
                          TotpSecretRepository totpSecretRepository,
                          UserService userService,
                          AuditService auditService) {
        this.totpService = totpService;
        this.totpSecretRepository = totpSecretRepository;
        this.userService = userService;
        this.auditService = auditService;
    }

    @GetMapping("/setup")
    public String setup(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam(value = "mandatory", required = false, defaultValue = "false") boolean mandatory,
            HttpSession session,
            Model model
    ) {
        if (userDetails == null) {
            return "redirect:/login";
        }

        String secret = totpService.generateSecret();
        List<String> recoveryCodes = totpService.generateRecoveryCodes();
        String qrCodeUri = totpService.generateQrCodeDataUri(userDetails.getUsername(), secret);

        session.setAttribute("TEMP_TOTP_SECRET", secret);
        session.setAttribute("TEMP_RECOVERY_CODES", recoveryCodes);

        model.addAttribute("secretKey", secret);
        model.addAttribute("qrCodeUri", qrCodeUri);
        model.addAttribute("recoveryCodes", recoveryCodes);
        model.addAttribute("mandatory", mandatory);
        return "totp-setup";
    }

    @PostMapping("/enable")
    public String enable(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam("code") String code,
            HttpSession session,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes,
            Model model
    ) {
        if (userDetails == null) return "redirect:/login";

        String tempSecret = (String) session.getAttribute("TEMP_TOTP_SECRET");
        @SuppressWarnings("unchecked")
        List<String> recoveryCodes = (List<String>) session.getAttribute("TEMP_RECOVERY_CODES");

        if (tempSecret == null || recoveryCodes == null) {
            return "redirect:/totp/setup";
        }

        boolean valid = totpService.verifyTotp(tempSecret, code.trim());
        if (!valid) {
            model.addAttribute("errorMessage", "Mã xác thực 6 chữ số không chính xác. Vui lòng thử lại.");
            model.addAttribute("secretKey", tempSecret);
            model.addAttribute("qrCodeUri", totpService.generateQrCodeDataUri(userDetails.getUsername(), tempSecret));
            model.addAttribute("recoveryCodes", recoveryCodes);
            model.addAttribute("mandatory", true);
            return "totp-setup";
        }

        AppUser user = userService.findById(userDetails.getId()).orElseThrow();
        String encryptedSecret = totpService.encryptSecret(tempSecret);
        String recoveryCodesStr = String.join(",", recoveryCodes);

        TotpSecret totpSecret = totpSecretRepository.findById(user.getId())
                .orElseGet(() -> {
                    TotpSecret ts = new TotpSecret();
                    ts.setUserId(user.getId());
                    ts.setNewEntity(true);
                    return ts;
                });

        totpSecret.setEncryptedSecret(encryptedSecret);
        totpSecret.setEnabled(true);
        totpSecret.setRecoveryCodes(recoveryCodesStr);
        totpSecretRepository.save(totpSecret);

        session.removeAttribute("TEMP_TOTP_SECRET");
        session.removeAttribute("TEMP_RECOVERY_CODES");
        session.setAttribute("TOTP_VERIFIED", true);

        String ip = AuditService.getClientIp(request);
        String ua = AuditService.getUserAgent(request);
        auditService.logEvent(user.getId(), user.getUsername(), "TOTP_ENABLED", ip, ua, "2FA TOTP successfully activated.");

        redirectAttributes.addFlashAttribute("successMessage", "Xác thực 2 bước (TOTP) đã được kích hoạt thành công!");
        return "redirect:/";
    }

    @GetMapping("/verify")
    public String verifyPage(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            HttpSession session,
            Model model
    ) {
        if (userDetails == null) return "redirect:/login";
        if (Boolean.TRUE.equals(session.getAttribute("TOTP_VERIFIED"))) {
            return "redirect:/";
        }
        return "totp-verify";
    }

    @PostMapping("/verify")
    public String verifyCode(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestParam("code") String code,
            HttpSession session,
            HttpServletRequest request,
            Model model
    ) {
        if (userDetails == null) return "redirect:/login";

        Optional<TotpSecret> optSecret = totpSecretRepository.findByUserId(userDetails.getId());
        if (optSecret.isEmpty() || !optSecret.get().isEnabled()) {
            session.setAttribute("TOTP_VERIFIED", true);
            return "redirect:/";
        }

        TotpSecret totpSecret = optSecret.get();
        String plainSecret = totpService.decryptSecret(totpSecret.getEncryptedSecret());
        String trimmedCode = code.trim().toUpperCase();

        String ip = AuditService.getClientIp(request);
        String ua = AuditService.getUserAgent(request);

        // Check TOTP code
        if (totpService.verifyTotp(plainSecret, trimmedCode)) {
            session.setAttribute("TOTP_VERIFIED", true);
            auditService.logEvent(userDetails.getId(), userDetails.getUsername(), "TOTP_VERIFY_SUCCESS", ip, ua, "TOTP 2FA passed.");
            return "redirect:/";
        }

        // Check Recovery Codes
        List<String> recoveryList = new ArrayList<>(Arrays.asList(totpSecret.getRecoveryCodes().split(",")));
        if (recoveryList.contains(trimmedCode)) {
            recoveryList.remove(trimmedCode);
            totpSecret.setRecoveryCodes(String.join(",", recoveryList));
            totpSecretRepository.save(totpSecret);

            session.setAttribute("TOTP_VERIFIED", true);
            auditService.logEvent(userDetails.getId(), userDetails.getUsername(), "TOTP_RECOVERY_USED", ip, ua, "Used one-time recovery code.");
            return "redirect:/";
        }

        auditService.logEvent(userDetails.getId(), userDetails.getUsername(), "TOTP_VERIFY_FAILURE", ip, ua, "Invalid TOTP code or recovery code.");
        model.addAttribute("errorMessage", "Mã xác thực hoặc mã khôi phục không hợp lệ. Vui lòng thử lại.");
        return "totp-verify";
    }
}
