package com.senior.cyber.pki.dao.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "tbl_intermediate")
public class Intermediate implements Serializable {

    public static final String STATUS_GOOD = "Good";
    public static final String STATUS_REVOKED = "Revoked";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "intermediate_id")
    private Long id;

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
    private String status;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

    @Column(name = "serial")
    private Long serial;

    public Long getId() {
        return id;
    }

    public String getRevokedReason() {
        return revokedReason;
    }

    public void setRevokedReason(String revokedReason) {
        this.revokedReason = revokedReason;
    }

    public Date getRevokedDate() {
        return revokedDate;
    }

    public void setRevokedDate(Date revokedDate) {
        this.revokedDate = revokedDate;
    }

    public Long getSerial() {
        return serial;
    }

    public void setSerial(Long serial) {
        this.serial = serial;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getOrganizationalUnit() {
        return organizationalUnit;
    }

    public void setOrganizationalUnit(String organizationalUnit) {
        this.organizationalUnit = organizationalUnit;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getLocalityName() {
        return localityName;
    }

    public void setLocalityName(String localityName) {
        this.localityName = localityName;
    }

    public String getStateOrProvinceName() {
        return stateOrProvinceName;
    }

    public void setStateOrProvinceName(String stateOrProvinceName) {
        this.stateOrProvinceName = stateOrProvinceName;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

//    public String getCrlUrl() {
//        return crlUrl;
//    }
//
//    public void setCrlUrl(String crlUrl) {
//        this.crlUrl = crlUrl;
//    }
//
//    public String getOcspUrl() {
//        return ocspUrl;
//    }
//
//    public void setOcspUrl(String ocspUrl) {
//        this.ocspUrl = ocspUrl;
//    }
//
//    public String getCaUrl() {
//        return caUrl;
//    }
//
//    public void setCaUrl(String caUrl) {
//        this.caUrl = caUrl;
//    }

    public Root getRoot() {
        return root;
    }

    public void setRoot(Root root) {
        this.root = root;
    }

}
