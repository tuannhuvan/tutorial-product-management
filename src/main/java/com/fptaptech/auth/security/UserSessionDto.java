package com.fptaptech.auth.security;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserSessionDto implements java.io.Serializable {
    private static final long serialVersionUID = 1L;

    private String sessionId;
    private Instant creationTime;
    private Instant lastAccessTime;
    private boolean current;
    private String ipAddress;
    private String userAgent;
}
