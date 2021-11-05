package com.senior.cyber.pki.web.dto;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.internal.bind.DateTypeAdapter;
import com.senior.cyber.pki.web.gson.Iso8601Date;

import java.util.Date;
import java.util.List;

public class SubjectDto {

    @Expose
    @SerializedName("rootCommonName")
    private String rootCommonName;

    @Expose
    @SerializedName("intermediateCommonName")
    private String intermediateCommonName;

    @Expose
    @SerializedName("country")
    private String country;

    @Expose
    @SerializedName("organization")
    private String organization;

    @Expose
    @SerializedName("organizationalUnit")
    private String organizationalUnit;

    @Expose
    @SerializedName("commonName")
    private String commonName;

    @Expose
    @SerializedName("localityName")
    private String localityName;

    @Expose
    @SerializedName("stateOrProvinceName")
    private String stateOrProvinceName;

    @Expose
    @SerializedName("emailAddress")
    private String emailAddress;

    @Expose
    @SerializedName("validFrom")
    @JsonAdapter(Iso8601Date.class)
    private Date validFrom;

    @Expose
    @SerializedName("validUtil")
    @JsonAdapter(Iso8601Date.class)
    private Date validUtil;

    @Expose
    @SerializedName("subjectAltNames")
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
