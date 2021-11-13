package com.senior.cyber.pki.web.repository;

import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.dao.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RootRepository extends JpaRepository<Root, Long> {

    Optional<Root> findBySerial(long serial);

    Optional<Root> findByIdAndUser(long id, User user);

    Optional<Root> findByCommonNameAndStatus(String commonName, String status);

    Optional<Root> findByCommonNameAndUserAndStatus(String commonName, User user, String status);

    Optional<Root> findByOrganizationAndStatus(String organization, String status);

    Optional<Root> findByOrganizationAndUserAndStatus(String organization, User user, String status);

}
