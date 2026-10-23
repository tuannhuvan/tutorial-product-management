package com.fptaptech.auth.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface EmailTokenRepository extends JpaRepository<EmailToken, Long> {

    Optional<EmailToken> findByTokenHashAndTokenTypeAndUsedFalse(String tokenHash, String tokenType);

    java.util.List<EmailToken> findByUserAndTokenType(AppUser user, String tokenType);

    @Query("SELECT COUNT(t) FROM EmailToken t WHERE t.user = :user AND t.tokenType = :tokenType AND t.expiresAt > :cutoff")
    long countRecentTokensByUser(
            @Param("user") AppUser user,
            @Param("tokenType") String tokenType,
            @Param("cutoff") LocalDateTime cutoff
    );

    @Modifying
    @Query("UPDATE EmailToken t SET t.used = true WHERE t.user = :user AND t.tokenType = :tokenType")
    void invalidateTokensByUserAndType(@Param("user") AppUser user, @Param("tokenType") String tokenType);
}
