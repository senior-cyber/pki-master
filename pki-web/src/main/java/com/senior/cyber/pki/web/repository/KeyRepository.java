package com.senior.cyber.pki.web.repository;

import com.senior.cyber.pki.dao.entity.Key;
import com.senior.cyber.pki.dao.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface KeyRepository extends JpaRepository<Key, String> {

    Optional<Key> findByClientId(String clientId);

    List<Key> findByUser(User user);

}
