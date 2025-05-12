package com.senior.cyber.pki.dao.repository.cluster;

import com.senior.cyber.pki.dao.entity.cluster.HttpSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface HttpSessionRepository extends JpaRepository<HttpSession, String> {

    Page<HttpSession> findAllByPrincipalName(String principalName, Pageable pageable);

    List<HttpSession> findAllBySessionId(String sessionId);
}
