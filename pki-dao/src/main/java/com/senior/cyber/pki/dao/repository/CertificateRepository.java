package com.senior.cyber.pki.dao.repository;

import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, String> {

    Optional<Certificate> findBySerial(long serial);

    List<Certificate> findByIssuerCertificate(Certificate issuerCertificate);

    Optional<Certificate> findByCommonNameAndStatus(String commonName, CertificateStatusEnum status);

    Optional<Certificate> findByOrganizationAndStatus(String organization, CertificateStatusEnum status);

    Optional<Certificate> findByOrganizationAndUserAndStatus(String organization, User user, CertificateStatusEnum status);

    Optional<Certificate> findByCommonNameAndUserAndStatus(String commonName, User user, CertificateStatusEnum status);

    Optional<Certificate> findByIdAndUser(String id, User user);

}
