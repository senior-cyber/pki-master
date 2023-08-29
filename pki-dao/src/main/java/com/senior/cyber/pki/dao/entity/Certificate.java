package com.senior.cyber.pki.dao.entity;

import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.type.CertificateAttributeConverter;
import com.senior.cyber.pki.dao.type.PrivateKeyAttributeConverter;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

@Entity
@Table(name = "tbl_certificate")
@Getter
@Setter
public class Certificate implements Serializable {

    @Id
    @UuidGenerator
    @Column(name = "certificate_id")
    @Setter(AccessLevel.NONE)
    private String id;

    @Column(name = "country_code")
    private String countryCode;

    @Column(name = "organization")
    private String organization;

    @Column(name = "organizational_unit")
    private String organizationalUnit;

    @Column(name = "common_name")
    private String commonName;

    @Column(name = "locality_name")
    private String localityName;

    @Column(name = "state_or_province_name")
    private String stateOrProvinceName;

    @Column(name = "email_address")
    private String emailAddress;

    @Convert(converter = PrivateKeyAttributeConverter.class)
    @Column(name = "private_key_pem")
    private PrivateKey privateKey;

    @Convert(converter = CertificateAttributeConverter.class)
    @Column(name = "certificate_pem")
    private X509Certificate certificate;

    @Column(name = "san")
    private String san;

    @Column(name = "serial")
    private Long serial;

    @Temporal(TemporalType.DATE)
    @Column(name = "valid_from")
    private Date validFrom;

    @Temporal(TemporalType.DATE)
    @Column(name = "valid_until")
    private Date validUntil;

    @Temporal(TemporalType.DATE)
    @Column(name = "revoked_date")
    private Date revokedDate;

    @Column(name = "revoked_reason")
    private String revokedReason;

    @ManyToOne
    @JoinColumn(name = "intermediate_id", referencedColumnName = "intermediate_id")
    private Intermediate intermediate;

    @ManyToOne
    @JoinColumn(name = "issuer_certificate_id", referencedColumnName = "certificate_id")
    private Certificate issuerCertificate;

    @ManyToOne
    @JoinColumn(name = "crl_certificate_id", referencedColumnName = "certificate_id")
    private Certificate crlCertificate;

    @ManyToOne
    @JoinColumn(name = "ocsp_certificate_id", referencedColumnName = "certificate_id")
    private Certificate ocspCertificate;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private CertificateStatusEnum status;

    @Column(name = "type")
    @Enumerated(EnumType.STRING)
    private CertificateTypeEnum type;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

}
