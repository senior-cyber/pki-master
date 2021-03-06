package com.senior.cyber.pki.dao.entity;

import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;
import java.util.Date;

@StaticMetamodel(Root.class)
public abstract class Root_ {

    public static volatile SingularAttribute<Root, Long> id;

    public static volatile SingularAttribute<Root, Long> serial;

    public static volatile SingularAttribute<Root, String> countryCode;
    public static volatile SingularAttribute<Root, String> organization;
    public static volatile SingularAttribute<Root, String> organizationalUnit;
    public static volatile SingularAttribute<Root, String> commonName;
    public static volatile SingularAttribute<Root, String> localityName;
    public static volatile SingularAttribute<Root, String> stateOrProvinceName;
    public static volatile SingularAttribute<Root, String> emailAddress;

    public static volatile SingularAttribute<Root, String> privateKey;
    public static volatile SingularAttribute<Root, String> certificate;

    public static volatile SingularAttribute<Root, Date> validFrom;
    public static volatile SingularAttribute<Root, Date> validUntil;
    public static volatile SingularAttribute<Root, Date> revokedDate;

    public static volatile SingularAttribute<Root, String> status;

    public static volatile SingularAttribute<Root, User> user;

    public Root_() {
    }

}