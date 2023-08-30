package com.senior.cyber.pki.root.web.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;
import java.util.List;

public class SubjectDto {

    @JsonProperty("rootCommonName")
    private String rootCommonName;

    @JsonProperty("intermediateCommonName")
    private String intermediateCommonName;

    @JsonProperty("country")
    private String country;

    @JsonProperty("organization")
    private String organization;

    @JsonProperty("organizationalUnit")
    private String organizationalUnit;

    @JsonProperty("commonName")
    private String commonName;

    @JsonProperty("localityName")
    private String localityName;

    @JsonProperty("stateOrProvinceName")
    private String stateOrProvinceName;

    @JsonProperty("emailAddress")
    private String emailAddress;

    @JsonFormat(pattern = "yyyy-MM-dd")
    @JsonProperty("validFrom")
    private Date validFrom;

    @JsonFormat(pattern = "yyyy-MM-dd")
    @JsonProperty("validUtil")
    private Date validUtil;

    @JsonProperty("subjectAltNames")
    private List<String> subjectAltNames;

    public List<String> getSubjectAltNames() {
        return subjectAltNames;
    }

    public void setSubjectAltNames(List<String> subjectAltNames) {
        this.subjectAltNames = subjectAltNames;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidUtil() {
        return validUtil;
    }

    public void setValidUtil(Date validUtil) {
        this.validUtil = validUtil;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
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

    public String getRootCommonName() {
        return rootCommonName;
    }

    public void setRootCommonName(String rootCommonName) {
        this.rootCommonName = rootCommonName;
    }

    public String getIntermediateCommonName() {
        return intermediateCommonName;
    }

    public void setIntermediateCommonName(String intermediateCommonName) {
        this.intermediateCommonName = intermediateCommonName;
    }

}
