package com.fptaptech.auth.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    java.util.List<AuditLog> findByUsername(String username);

    @Query("SELECT a FROM AuditLog a WHERE " +
           "(:eventType IS NULL OR :eventType = '' OR a.eventType = :eventType) AND " +
           "(:username IS NULL OR :username = '' OR LOWER(a.username) LIKE LOWER(CONCAT('%', :username, '%'))) AND " +
           "(:ipAddress IS NULL OR :ipAddress = '' OR a.ipAddress = :ipAddress) AND " +
           "(:fromTime IS NULL OR a.createdAt >= :fromTime) AND " +
           "(:toTime IS NULL OR a.createdAt <= :toTime) " +
           "ORDER BY a.createdAt DESC")
    Page<AuditLog> searchLogs(
            @Param("eventType") String eventType,
            @Param("username") String username,
            @Param("ipAddress") String ipAddress,
            @Param("fromTime") LocalDateTime fromTime,
            @Param("toTime") LocalDateTime toTime,
            Pageable pageable
    );
}
