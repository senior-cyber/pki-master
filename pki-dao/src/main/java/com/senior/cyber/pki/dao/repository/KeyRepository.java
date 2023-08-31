package com.senior.cyber.pki.dao.repository;

import com.senior.cyber.pki.dao.entity.Key;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface KeyRepository extends JpaRepository<Key, String> {

    Optional<Key> findBySerial(long serial);

}
