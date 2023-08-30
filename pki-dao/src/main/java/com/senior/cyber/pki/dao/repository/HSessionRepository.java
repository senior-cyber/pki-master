package com.senior.cyber.pki.dao.repository;

import com.senior.cyber.pki.dao.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface HSessionRepository extends JpaRepository<Session, String> {

    Optional<Session> findBySessionId(String sessionId);

    List<Session> findByLogin(String login);

}
