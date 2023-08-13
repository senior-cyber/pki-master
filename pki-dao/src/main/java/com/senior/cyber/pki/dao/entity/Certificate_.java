package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

import java.util.Date;

@StaticMetamodel(Certificate.class)
public abstract class Certificate_ {

    public static volatile SingularAttribute<Certificate, Long> id;

    public static volatile SingularAttribute<Certificate, Long> serial;

    public static volatile SingularAttribute<Certificate, String> san;

    public static volatile SingularAttribute<Certificate, String> countryCode;
    public static volatile SingularAttribute<Certificate, String> organization;
    public static volatile SingularAttribute<Certificate, String> organizationalUnit;
    public static volatile SingularAttribute<Certificate, String> commonName;
    public static volatile SingularAttribute<Certificate, String> localityName;
    public static volatile SingularAttribute<Certificate, String> stateOrProvinceName;
    public static volatile SingularAttribute<Certificate, String> emailAddress;

    public static volatile SingularAttribute<Certificate, String> privateKey;
    public static volatile SingularAttribute<Certificate, String> certificate;

    public static volatile SingularAttribute<Certificate, Date> validFrom;
    public static volatile SingularAttribute<Certificate, Date> validUntil;
    public static volatile SingularAttribute<Certificate, Date> revokedDate;
    public static volatile SingularAttribute<Certificate, String> revokedReason;

    public static volatile SingularAttribute<Certificate, Intermediate> intermediate;

    public static volatile SingularAttribute<Certificate, String> status;

    public static volatile SingularAttribute<Certificate, User> user;

    public Certificate_() {
    }

}