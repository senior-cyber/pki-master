package com.senior.cyber.pki.dao.repository.pki;

import com.senior.cyber.pki.dao.entity.pki.Certificate;
import com.senior.cyber.pki.dao.entity.pki.Key;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, String> {

    Optional<Certificate> findBySerial(long serial);

    Optional<Certificate> findBySerialAndUser(long serial, User user);

    List<Certificate> findByUserAndStatusAndTypeIn(User user, CertificateStatusEnum status, Collection<CertificateTypeEnum> types);

    List<Certificate> findByUserAndStatusAndType(User user, CertificateStatusEnum status, CertificateTypeEnum type);

    List<Certificate> findByIssuerCertificate(Certificate issuerCertificate);

    Optional<Certificate> findByCommonNameAndStatus(String commonName, CertificateStatusEnum status);

    Optional<Certificate> findByOrganizationAndStatus(String organization, CertificateStatusEnum status);

    Optional<Certificate> findByOrganizationAndUserAndStatus(String organization, User user, CertificateStatusEnum status);

    Optional<Certificate> findByCommonNameAndUserAndStatus(String commonName, User user, CertificateStatusEnum status);

    Optional<Certificate> findByIdAndUser(String id, User user);

    List<Certificate> findByType(CertificateTypeEnum type);

    boolean existsByIssuerCertificateAndType(Certificate issuerCertificate, CertificateTypeEnum type);

    boolean existsBySerial(Long serial);

    List<Certificate> findByIssuerCertificateAndType(Certificate issuerCertificate, CertificateTypeEnum type);

    List<Certificate> findByKey(Key key);

}
