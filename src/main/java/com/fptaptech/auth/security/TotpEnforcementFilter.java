package com.fptaptech.auth.security;

import com.fptaptech.auth.user.TotpSecret;
import com.fptaptech.auth.user.TotpSecretRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@Slf4j
public class TotpEnforcementFilter extends OncePerRequestFilter {

    private final TotpSecretRepository totpSecretRepository;

    public TotpEnforcementFilter(TotpSecretRepository totpSecretRepository) {
        super();
        this.totpSecretRepository = totpSecretRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // Skip static resources and auth endpoints
        if (path.startsWith("/css") || path.startsWith("/js") || path.startsWith("/images")
                || path.startsWith("/webjars") || path.equals("/login") || path.equals("/logout")
                || path.startsWith("/registration") || path.startsWith("/verify-email")
                || path.startsWith("/forgot-password") || path.startsWith("/reset-password")
                || path.startsWith("/totp")) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
            boolean isStaff = userDetails.getUser().hasRole("ROLE_LECTURER") || userDetails.getUser().hasRole("ROLE_ADMIN");
            Optional<TotpSecret> optSecret = totpSecretRepository.findByUserId(userDetails.getId());
            HttpSession session = request.getSession(false);

            if (isStaff) {
                if (optSecret.isEmpty() || !optSecret.get().isEnabled()) {
                    // Mandatory setup for Lecturer and Admin
                    response.sendRedirect(request.getContextPath() + "/totp/setup?mandatory=true");
                    return;
                } else {
                    // 2FA is enabled -> must be verified in this session
                    boolean isTotpVerified = session != null && Boolean.TRUE.equals(session.getAttribute("TOTP_VERIFIED"));
                    if (!isTotpVerified) {
                        response.sendRedirect(request.getContextPath() + "/totp/verify");
                        return;
                    }
                }
            } else if (optSecret.isPresent() && optSecret.get().isEnabled()) {
                // Student has voluntarily enabled 2FA
                boolean isTotpVerified = session != null && Boolean.TRUE.equals(session.getAttribute("TOTP_VERIFIED"));
                if (!isTotpVerified) {
                    response.sendRedirect(request.getContextPath() + "/totp/verify");
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
