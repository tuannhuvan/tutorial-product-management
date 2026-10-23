package com.fptaptech.auth.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Slf4j
public class SessionManagementService {

    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
    private final PersistentTokenRepository persistentTokenRepository;

    public SessionManagementService(
            @Autowired(required = false) FindByIndexNameSessionRepository<? extends Session> sessionRepository,
            @Lazy @Autowired(required = false) PersistentTokenRepository persistentTokenRepository
    ) {
        this.sessionRepository = sessionRepository;
        this.persistentTokenRepository = persistentTokenRepository;
    }

    public List<UserSessionDto> getUserSessions(String username, String currentSessionId) {
        List<UserSessionDto> result = new ArrayList<>();
        if (sessionRepository == null || username == null) {
            return result;
        }

        try {
            Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);
            for (Map.Entry<String, ? extends Session> entry : sessions.entrySet()) {
                Session session = entry.getValue();
                boolean isCurrent = entry.getKey().equals(currentSessionId);
                String ip = session.getAttribute("SESSION_IP");
                String ua = session.getAttribute("SESSION_UA");

                result.add(UserSessionDto.builder()
                        .sessionId(entry.getKey())
                        .creationTime(session.getCreationTime())
                        .lastAccessTime(session.getLastAccessedTime())
                        .current(isCurrent)
                        .ipAddress(ip != null ? ip : "Unknown")
                        .userAgent(ua != null ? ua : "Web Browser")
                        .build());
            }
        } catch (Exception e) {
            log.warn("Could not retrieve sessions for {}: {}", username, e.getMessage());
        }

        return result;
    }

    public void terminateSession(String username, String sessionId) {
        if (sessionRepository == null) return;
        try {
            sessionRepository.deleteById(sessionId);
            log.info("Terminated session {} for user {}", sessionId, username);
        } catch (Exception e) {
            log.error("Failed to terminate session {}: {}", sessionId, e.getMessage());
        }
    }

    public void terminateAllSessionsExceptCurrent(String username, String currentSessionId) {
        if (sessionRepository == null) return;
        try {
            Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);
            for (String sId : sessions.keySet()) {
                if (!sId.equals(currentSessionId)) {
                    sessionRepository.deleteById(sId);
                }
            }
            revokeRememberMeTokens(username);
            log.info("Terminated all sessions except current for user {}", username);
        } catch (Exception e) {
            log.error("Failed to terminate other sessions for {}: {}", username, e.getMessage());
        }
    }

    public void terminateAllSessions(String username) {
        if (sessionRepository != null) {
            try {
                Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);
                for (String sId : sessions.keySet()) {
                    sessionRepository.deleteById(sId);
                }
                log.info("Terminated all active sessions for user {}", username);
            } catch (Exception e) {
                log.error("Failed to terminate all sessions for {}: {}", username, e.getMessage());
            }
        }
        revokeRememberMeTokens(username);
    }

    public void revokeRememberMeTokens(String username) {
        if (persistentTokenRepository != null) {
            try {
                persistentTokenRepository.removeUserTokens(username);
                log.info("Revoked persistent remember-me tokens for user {}", username);
            } catch (Exception e) {
                log.warn("Could not revoke remember-me tokens for {}: {}", username, e.getMessage());
            }
        }
    }
}
