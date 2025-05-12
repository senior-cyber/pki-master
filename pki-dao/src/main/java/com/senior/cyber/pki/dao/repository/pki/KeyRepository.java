package com.senior.cyber.pki.dao.repository.pki;

import com.senior.cyber.pki.dao.entity.pki.Key;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KeyRepository extends JpaRepository<Key, String> {

    Key findBySerial(long serial);

}
