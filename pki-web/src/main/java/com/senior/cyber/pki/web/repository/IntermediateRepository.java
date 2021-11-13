package com.senior.cyber.pki.web.repository;

import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.dao.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IntermediateRepository extends JpaRepository<Intermediate, Long> {

    Optional<Intermediate> findBySerial(long serial);

    Optional<Intermediate> findByIdAndUser(long id, User user);

    Optional<Intermediate> findBySerialAndRoot(long serial, Root root);

    List<Intermediate> findByRoot(Root root);

    List<Intermediate> findByRootAndStatus(Root root, String status);

    Optional<Intermediate> findByCommonNameAndStatus(String commonName, String status);

    Optional<Intermediate> findByCommonNameAndUserAndStatus(String commonName, User user, String status);

    Optional<Intermediate> findByOrganizationAndStatus(String organization, String status);

    Optional<Intermediate> findByOrganizationAndUserAndStatus(String organization, User user, String status);

}
