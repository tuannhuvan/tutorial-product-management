package com.fptaptech.auth.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<AppUser, Long> {

    @Override
    @EntityGraph(attributePaths = {"roles"})
    Optional<AppUser> findById(Long id);

    @EntityGraph(attributePaths = {"roles"})
    Optional<AppUser> findByUsername(String username);

    @EntityGraph(attributePaths = {"roles"})
    Optional<AppUser> findByEmail(String email);

    @EntityGraph(attributePaths = {"roles"})
    @Query("SELECT u FROM AppUser u WHERE u.username = :keyword OR u.email = :keyword")
    Optional<AppUser> findByUsernameOrEmail(@Param("keyword") String keyword);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Query("SELECT COUNT(u) FROM AppUser u JOIN u.roles r WHERE r.name = :roleName AND u.status = :status")
    long countByRoleNameAndStatus(@Param("roleName") String roleName, @Param("status") UserStatus status);

    @EntityGraph(attributePaths = {"roles"})
    @Query("SELECT DISTINCT u FROM AppUser u LEFT JOIN u.roles r WHERE " +
           "(:query IS NULL OR :query = '' OR LOWER(u.username) LIKE LOWER(CONCAT('%', :query, '%')) OR LOWER(u.email) LIKE LOWER(CONCAT('%', :query, '%'))) " +
           "AND (:status IS NULL OR u.status = :status) " +
           "AND (:roleName IS NULL OR :roleName = '' OR r.name = :roleName)")
    Page<AppUser> searchUsers(
            @Param("query") String query,
            @Param("status") UserStatus status,
            @Param("roleName") String roleName,
            Pageable pageable
    );
}
