package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

import java.util.Date;

@StaticMetamodel(Intermediate.class)
public abstract class Intermediate_ {

    public static volatile SingularAttribute<Intermediate, Long> id;

    public static volatile SingularAttribute<Intermediate, Long> serial;

    public static volatile SingularAttribute<Intermediate, String> countryCode;
    public static volatile SingularAttribute<Intermediate, String> organization;
    public static volatile SingularAttribute<Intermediate, String> organizationalUnit;
    public static volatile SingularAttribute<Intermediate, String> commonName;
    public static volatile SingularAttribute<Intermediate, String> localityName;
    public static volatile SingularAttribute<Intermediate, String> stateOrProvinceName;
    public static volatile SingularAttribute<Intermediate, String> emailAddress;

    public static volatile SingularAttribute<Intermediate, String> privateKey;
    public static volatile SingularAttribute<Intermediate, String> certificate;

    public static volatile SingularAttribute<Intermediate, Date> validFrom;
    public static volatile SingularAttribute<Intermediate, Date> validUntil;
    public static volatile SingularAttribute<Intermediate, Date> revokedDate;
    public static volatile SingularAttribute<Intermediate, String> revokedReason;

    public static volatile SingularAttribute<Intermediate, Root> root;

    public static volatile SingularAttribute<Intermediate, String> status;

    public static volatile SingularAttribute<Intermediate, User> user;

    public Intermediate_() {
    }

}