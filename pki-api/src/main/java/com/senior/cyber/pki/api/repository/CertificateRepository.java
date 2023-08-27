package com.senior.cyber.pki.api.repository;

import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {
 
    Optional<Certificate> findBySerial(long serial);

    Optional<Certificate> findBySerialAndIntermediate(long serial, Intermediate intermediate);

    Optional<Certificate> findByIdAndUser(String id, User user);

    List<Certificate> findByIntermediate(Intermediate intermediate);

    List<Certificate> findByIntermediateAndStatus(Intermediate intermediate, CertificateStatusEnum status);

    Optional<Certificate> findByCommonNameAndUserAndStatus(String commonName, User user, CertificateStatusEnum status);

    Optional<Certificate> findByOrganizationAndUserAndStatus(String organization, User user, CertificateStatusEnum status);

}
