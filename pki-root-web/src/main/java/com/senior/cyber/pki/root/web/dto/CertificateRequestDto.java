package com.senior.cyber.pki.root.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.senior.cyber.frmk.common.jackson.*;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CertificateRequestDto {

    @JsonProperty("csr")
    @JsonSerialize(using = CsrSerializer.class)
    @JsonDeserialize(using = CsrDeserializer.class)
    private PKCS10CertificationRequest csr;

    @JsonProperty("duration")
    private Integer duration;

    @JsonProperty("issuerCertificate")
    @JsonSerialize(using = CertificateSerializer.class)
    @JsonDeserialize(using = CertificateDeserializer.class)
    private X509Certificate issuerCertificate;

    @JsonProperty("issuerPrivateKey")
    @JsonSerialize(using = PrivateKeySerializer.class)
    @JsonDeserialize(using = PrivateKeyDeserializer.class)
    private PrivateKey issuerPrivateKey;

    @JsonProperty("basicConstraints")
    private boolean basicConstraints;

    @JsonProperty("keyUsage")
    private List<KeyUsage> keyUsage;

    @JsonProperty("extendedKeyUsage")
    private List<ExtendedKeyUsage> extendedKeyUsage;

    @JsonProperty("subjectAlternativeName")
    private List<GeneralNameDto> subjectAlternativeName = new ArrayList<>();

    @JsonProperty("cRLDistributionPoints")
    private List<GeneralNameDto> cRLDistributionPoints = new ArrayList<>();

    @JsonProperty("authorityInfoAccess")
    private List<GeneralNameDto> authorityInfoAccess = new ArrayList<>();

    @JsonProperty("serial")
    private Long serial = System.currentTimeMillis();

    @JsonProperty("basicConstraintsCritical")
    private boolean basicConstraintsCritical = true;

    @JsonProperty("subjectKeyIdentifierCritical")
    private boolean subjectKeyIdentifierCritical = true;

    @JsonProperty("authorityKeyIdentifierCritical")
    private boolean authorityKeyIdentifierCritical = true;

    @JsonProperty("keyUsageCritical")
    private boolean keyUsageCritical = true;

    @JsonProperty("extendedKeyUsageCritical")
    private boolean extendedKeyUsageCritical = true;

    @JsonProperty("cRLDistributionPointsCritical")
    private boolean cRLDistributionPointsCritical = true;

    @JsonProperty("authorityInfoAccessCritical")
    private boolean authorityInfoAccessCritical = true;

    @JsonProperty("subjectAlternativeNameCritical")
    private boolean subjectAlternativeNameCritical = true;

    public List<GeneralNameDto> getcRLDistributionPoints() {
        return cRLDistributionPoints;
    }

    public void setcRLDistributionPoints(List<GeneralNameDto> cRLDistributionPoints) {
        this.cRLDistributionPoints = cRLDistributionPoints;
    }

    public boolean isBasicConstraintsCritical() {
        return basicConstraintsCritical;
    }

    public void setBasicConstraintsCritical(boolean basicConstraintsCritical) {
        this.basicConstraintsCritical = basicConstraintsCritical;
    }

    public boolean isSubjectKeyIdentifierCritical() {
        return subjectKeyIdentifierCritical;
    }

    public void setSubjectKeyIdentifierCritical(boolean subjectKeyIdentifierCritical) {
        this.subjectKeyIdentifierCritical = subjectKeyIdentifierCritical;
    }

    public boolean isAuthorityKeyIdentifierCritical() {
        return authorityKeyIdentifierCritical;
    }

    public void setAuthorityKeyIdentifierCritical(boolean authorityKeyIdentifierCritical) {
        this.authorityKeyIdentifierCritical = authorityKeyIdentifierCritical;
    }

    public boolean isKeyUsageCritical() {
        return keyUsageCritical;
    }

    public void setKeyUsageCritical(boolean keyUsageCritical) {
        this.keyUsageCritical = keyUsageCritical;
    }

    public boolean isExtendedKeyUsageCritical() {
        return extendedKeyUsageCritical;
    }

    public void setExtendedKeyUsageCritical(boolean extendedKeyUsageCritical) {
        this.extendedKeyUsageCritical = extendedKeyUsageCritical;
    }

    public boolean iscRLDistributionPointsCritical() {
        return cRLDistributionPointsCritical;
    }

    public void setcRLDistributionPointsCritical(boolean cRLDistributionPointsCritical) {
        this.cRLDistributionPointsCritical = cRLDistributionPointsCritical;
    }

    public boolean isAuthorityInfoAccessCritical() {
        return authorityInfoAccessCritical;
    }

    public void setAuthorityInfoAccessCritical(boolean authorityInfoAccessCritical) {
        this.authorityInfoAccessCritical = authorityInfoAccessCritical;
    }

    public boolean isSubjectAlternativeNameCritical() {
        return subjectAlternativeNameCritical;
    }

    public void setSubjectAlternativeNameCritical(boolean subjectAlternativeNameCritical) {
        this.subjectAlternativeNameCritical = subjectAlternativeNameCritical;
    }

    public Long getSerial() {
        return serial;
    }

    public void setSerial(Long serial) {
        this.serial = serial;
    }

    public PKCS10CertificationRequest getCsr() {
        return csr;
    }

    public void setCsr(PKCS10CertificationRequest csr) {
        this.csr = csr;
    }

    public Integer getDuration() {
        return duration;
    }

    public void setDuration(Integer days) {
        this.duration = days;
    }

    public X509Certificate getIssuerCertificate() {
        return issuerCertificate;
    }

    public void setIssuerCertificate(X509Certificate issuerCertificate) {
        this.issuerCertificate = issuerCertificate;
    }

    public PrivateKey getIssuerPrivateKey() {
        return issuerPrivateKey;
    }

    public void setIssuerPrivateKey(PrivateKey issuerPrivateKey) {
        this.issuerPrivateKey = issuerPrivateKey;
    }

    public boolean isBasicConstraints() {
        return basicConstraints;
    }

    public void setBasicConstraints(boolean basicConstraints) {
        this.basicConstraints = basicConstraints;
    }

    public List<KeyUsage> getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(List<KeyUsage> keyUsage) {
        this.keyUsage = keyUsage;
    }

    public List<ExtendedKeyUsage> getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    public void setExtendedKeyUsage(List<ExtendedKeyUsage> extendedKeyUsage) {
        this.extendedKeyUsage = extendedKeyUsage;
    }

    public List<GeneralNameDto> getSubjectAlternativeName() {
        return subjectAlternativeName;
    }

    public void setSubjectAlternativeName(List<GeneralNameDto> subjectAlternativeName) {
        this.subjectAlternativeName = subjectAlternativeName;
    }

    public List<GeneralNameDto> getCRLDistributionPoints() {
        return cRLDistributionPoints;
    }

    public void setCRLDistributionPoints(List<GeneralNameDto> cRLDistributionPoints) {
        this.cRLDistributionPoints = cRLDistributionPoints;
    }

    public List<GeneralNameDto> getAuthorityInfoAccess() {
        return authorityInfoAccess;
    }

    public void setAuthorityInfoAccess(List<GeneralNameDto> authorityInfoAccess) {
        this.authorityInfoAccess = authorityInfoAccess;
    }

}
