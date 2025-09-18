package com.senior.cyber.pki.dao.repository.pki;

import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.pki.Queue;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface QueueRepository extends JpaRepository<Queue, String> {

    List<Queue> findByIssuerKey(Key issuerKey);

    Optional<Queue> findFirstByOrderByPriorityAsc();

}
