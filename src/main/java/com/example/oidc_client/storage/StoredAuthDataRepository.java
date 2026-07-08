package com.example.oidc_client.storage;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface StoredAuthDataRepository extends JpaRepository<StoredAuthData, String> {

    Optional<StoredAuthData> findByRegistrationIdAndPrincipalName(
            String registrationId,
            String principalName
    );

    void deleteByRegistrationIdAndPrincipalName(
            String registrationId,
            String principalName
    );
}