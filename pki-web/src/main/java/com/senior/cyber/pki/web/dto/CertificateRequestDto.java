package com.senior.cyber.pki.web.dto;

import com.senior.cyber.pki.web.gson.CertificationSignRequestAdaptor;
import com.senior.cyber.pki.web.gson.PrivateKeyTypeAdapter;
import com.senior.cyber.pki.web.gson.X509CertificateTypeAdapter;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CertificateRequestDto {

    @Expose
    @SerializedName("csr")
    @JsonAdapter(CertificationSignRequestAdaptor.class)
    private PKCS10CertificationRequest csr;

    @Expose
    @SerializedName("duration")
    private Integer duration;

    @Expose
    @SerializedName("issuerCertificate")
    @JsonAdapter(X509CertificateTypeAdapter.class)
    private X509Certificate issuerCertificate;

    @Expose
    @SerializedName("issuerPrivateKey")
    @JsonAdapter(PrivateKeyTypeAdapter.class)
    private PrivateKey issuerPrivateKey;

    @Expose
    @SerializedName("basicConstraints")
    private boolean basicConstraints;

    @Expose
    @SerializedName("keyUsage")
    private List<KeyUsage> keyUsage;

    @Expose
    @SerializedName("extendedKeyUsage")
    private List<ExtendedKeyUsage> extendedKeyUsage;

    @Expose
    @SerializedName("subjectAlternativeName")
    private List<GeneralNameDto> subjectAlternativeName = new ArrayList<>();

    @Expose
    @SerializedName("cRLDistributionPoints")
    private List<GeneralNameDto> cRLDistributionPoints = new ArrayList<>();

    @Expose
    @SerializedName("authorityInfoAccess")
    private List<GeneralNameDto> authorityInfoAccess = new ArrayList<>();

    @Expose
    @SerializedName("serial")
    private Long serial = System.currentTimeMillis();

    @Expose
    @SerializedName("basicConstraintsCritical")
    private boolean basicConstraintsCritical = true;

    @Expose
    @SerializedName("subjectKeyIdentifierCritical")
    private boolean subjectKeyIdentifierCritical = true;

    @Expose
    @SerializedName("authorityKeyIdentifierCritical")
    private boolean authorityKeyIdentifierCritical = true;

    @Expose
    @SerializedName("keyUsageCritical")
    private boolean keyUsageCritical = true;

    @Expose
    @SerializedName("extendedKeyUsageCritical")
    private boolean extendedKeyUsageCritical = true;

    @Expose
    @SerializedName("cRLDistributionPointsCritical")
    private boolean cRLDistributionPointsCritical = true;

    @Expose
    @SerializedName("authorityInfoAccessCritical")
    private boolean authorityInfoAccessCritical = true;

    @Expose
    @SerializedName("subjectAlternativeNameCritical")
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
