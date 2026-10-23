package com.fptaptech.auth.user;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.domain.Persistable;

@Entity
@Table(name = "totp_secrets")
@Getter
@Setter
public class TotpSecret implements Persistable<Long>, java.io.Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "encrypted_secret", nullable = false, length = 255)
    private String encryptedSecret;

    @Column(nullable = false)
    private boolean enabled = false;

    @Column(name = "recovery_codes", nullable = false, columnDefinition = "TEXT")
    private String recoveryCodes;

    @Transient
    private boolean isNewEntity = false;

    public TotpSecret() {
        super();
    }

    public TotpSecret(Long userId, String encryptedSecret, boolean enabled, String recoveryCodes, boolean isNewEntity) {
        super();
        this.userId = userId;
        this.encryptedSecret = encryptedSecret;
        this.enabled = enabled;
        this.recoveryCodes = recoveryCodes;
        this.isNewEntity = isNewEntity;
    }

    @Override
    public Long getId() {
        return this.userId;
    }

    @Override
    public boolean isNew() {
        return this.isNewEntity;
    }
}
