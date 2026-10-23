package com.fptaptech.auth.config;

import com.fptaptech.auth.audit.AuditService;
import com.fptaptech.auth.security.CustomUserDetails;
import com.fptaptech.auth.security.TotpEnforcementFilter;
import com.fptaptech.auth.user.TotpSecret;
import com.fptaptech.auth.user.TotpSecretRepository;
import com.fptaptech.auth.user.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.sql.DataSource;
import java.util.Optional;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final TotpEnforcementFilter totpEnforcementFilter;

    public SecurityConfig(TotpEnforcementFilter totpEnforcementFilter) {
        this.totpEnforcementFilter = totpEnforcementFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
        repository.setDataSource(dataSource);
        return repository;
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(),
                new HttpSessionSecurityContextRepository()
        );
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(UserService userService, TotpSecretRepository totpSecretRepository) {
        return (request, response, authentication) -> {
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            String ip = AuditService.getClientIp(request);
            String ua = AuditService.getUserAgent(request);
            userService.handleLoginSuccess(userDetails.getUsername(), ip, ua);

            HttpSession session = request.getSession(true);
            session.setAttribute("SESSION_IP", ip);
            session.setAttribute("SESSION_UA", ua);

            boolean isStaff = userDetails.getUser().hasRole("ROLE_LECTURER") || userDetails.getUser().hasRole("ROLE_ADMIN");
            if (isStaff) {
                Optional<TotpSecret> secret = totpSecretRepository.findByUserId(userDetails.getId());
                if (secret.isEmpty() || !secret.get().isEnabled()) {
                    response.sendRedirect(request.getContextPath() + "/totp/setup?mandatory=true");
                    return;
                } else {
                    session.setAttribute("TOTP_VERIFIED", false);
                    response.sendRedirect(request.getContextPath() + "/totp/verify");
                    return;
                }
            }

            response.sendRedirect(request.getContextPath() + "/");
        };
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(UserService userService) {
        return (request, response, exception) -> {
            String username = request.getParameter("username");
            String ip = AuditService.getClientIp(request);
            String ua = AuditService.getUserAgent(request);
            if (username != null && !username.isBlank()) {
                userService.handleLoginFailure(username, ip, ua);
            }
            response.sendRedirect(request.getContextPath() + "/login?error");
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            PersistentTokenRepository persistentTokenRepository,
            AuthenticationSuccessHandler successHandler,
            AuthenticationFailureHandler failureHandler,
            SecurityContextRepository securityContextRepository
    ) throws Exception {

        http
            .securityContext(sc -> sc.securityContextRepository(securityContextRepository))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/login",
                    "/registration",
                    "/verify-email",
                    "/forgot-password",
                    "/reset-password",
                    "/resend-verification",
                    "/css/**",
                    "/js/**",
                    "/images/**",
                    "/webjars/**",
                    "/error"
                ).permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/lecturer/**").hasAnyRole("LECTURER", "ADMIN")
                .requestMatchers("/totp/**", "/me/**", "/").authenticated()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .permitAll()
            )
            .rememberMe(rm -> rm
                .tokenRepository(persistentTokenRepository)
                .tokenValiditySeconds(14 * 24 * 60 * 60) // 14 days
                .key("StudentPortalRememberMeKey2026")
                .rememberMeParameter("remember-me")
            )
            .sessionManagement(sm -> sm
                .maximumSessions(2)
                .maxSessionsPreventsLogin(false)
            )
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net;")
                )
            )
            .addFilterAfter(totpEnforcementFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
