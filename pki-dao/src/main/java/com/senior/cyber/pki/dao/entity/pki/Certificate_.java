package com.senior.cyber.pki.dao.entity.pki;

import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.common.dto.CertificateStatusEnum;
import com.senior.cyber.pki.common.dto.CertificateTypeEnum;
import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

import java.security.cert.X509Certificate;
import java.util.Date;

@StaticMetamodel(Certificate.class)
public abstract class Certificate_ {

    public static volatile SingularAttribute<Certificate, String> id;
    public static volatile SingularAttribute<Certificate, Long> serial;
    public static volatile SingularAttribute<Certificate, String> san;
    public static volatile SingularAttribute<Certificate, String> countryCode;
    public static volatile SingularAttribute<Certificate, String> organization;
    public static volatile SingularAttribute<Certificate, String> organizationalUnit;
    public static volatile SingularAttribute<Certificate, String> commonName;
    public static volatile SingularAttribute<Certificate, String> localityName;
    public static volatile SingularAttribute<Certificate, String> stateOrProvinceName;
    public static volatile SingularAttribute<Certificate, String> emailAddress;
    public static volatile SingularAttribute<Certificate, Key> key;
    public static volatile SingularAttribute<Certificate, X509Certificate> certificate;
    public static volatile SingularAttribute<Certificate, Date> createdDatetime;
    public static volatile SingularAttribute<Certificate, Date> validFrom;
    public static volatile SingularAttribute<Certificate, Date> validUntil;
    public static volatile SingularAttribute<Certificate, Date> revokedDate;
    public static volatile SingularAttribute<Certificate, String> revokedReason;
    public static volatile SingularAttribute<Certificate, CertificateStatusEnum> status;
    public static volatile SingularAttribute<Certificate, CertificateTypeEnum> type;
    public static volatile SingularAttribute<Certificate, Certificate> crlCertificate;
    public static volatile SingularAttribute<Certificate, Certificate> ocspCertificate;
    public static volatile SingularAttribute<Certificate, Certificate> issuerCertificate;
    public static volatile SingularAttribute<Certificate, User> user;

}