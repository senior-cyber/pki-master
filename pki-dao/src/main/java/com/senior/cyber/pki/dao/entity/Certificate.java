package com.senior.cyber.pki.dao.entity;

import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.type.X509CertificateType;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Date;

@Getter
@Setter
@Entity
@Table(name = "tbl_certificate")
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

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "key_id", referencedColumnName = "key_id")
    private Key key;

    @Convert(converter = X509CertificateType.class)
    @Column(name = "certificate_pem")
    private X509Certificate certificate;

    @Column(name = "san")
    private String san;

    @Column(name = "serial")
    private Long serial;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_datetime")
    private Date createdDatetime;

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

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "issuer_certificate_id", referencedColumnName = "certificate_id")
    private Certificate issuerCertificate;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "crl_certificate_id", referencedColumnName = "certificate_id")
    private Certificate crlCertificate;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "ocsp_certificate_id", referencedColumnName = "certificate_id")
    private Certificate ocspCertificate;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private CertificateStatusEnum status;

    @Column(name = "type")
    @Enumerated(EnumType.STRING)
    private CertificateTypeEnum type;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

}
