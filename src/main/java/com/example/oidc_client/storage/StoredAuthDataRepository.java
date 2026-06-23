package com.example.oidc_client.storage;

import org.springframework.data.jpa.repository.JpaRepository;

public interface StoredAuthDataRepository extends JpaRepository<StoredAuthData, String> {
}