package com.senior.cyber.pki.dao.entity;

import com.senior.cyber.pki.dao.enums.IntermediateStatusEnum;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "tbl_intermediate")
@Getter
@Setter
public class Intermediate implements Serializable {

    @Id
    @UuidGenerator
    @Column(name = "intermediate_id")
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

    @Column(name = "private_key")
    private String privateKey;

    @Column(name = "certificate")
    private String certificate;

//    @Column(name = "crl_url")
//    private String crlUrl;
//
//    @Column(name = "ocsp_url")
//    private String ocspUrl;
//
//    @Column(name = "ca_url")
//    private String caUrl;

    @ManyToOne
    @JoinColumn(name = "root_id", referencedColumnName = "root_id")
    private Root root;

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

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private IntermediateStatusEnum status;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

    @Column(name = "serial")
    private Long serial;

}
