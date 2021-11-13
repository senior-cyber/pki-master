package com.senior.cyber.pki.web.repository;

import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    Optional<Certificate> findBySerial(long serial);

    Optional<Certificate> findBySerialAndIntermediate(long serial, Intermediate intermediate);

    Optional<Certificate> findByIdAndUser(long id, User user);

    List<Certificate> findByIntermediate(Intermediate intermediate);

    List<Certificate> findByIntermediateAndStatus(Intermediate intermediate, String status);

    Optional<Certificate> findByCommonNameAndUserAndStatus(String commonName, User user, String status);

    Optional<Certificate> findByCommonNameAndStatus(String commonName, String status);

    Optional<Certificate> findByOrganizationAndStatus(String organization, String status);

    Optional<Certificate> findByOrganizationAndUserAndStatus(String organization, User user, String status);

}
