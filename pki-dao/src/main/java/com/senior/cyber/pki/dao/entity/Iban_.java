package com.senior.cyber.pki.dao.entity;

import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(Iban.class)
public abstract class Iban_ {

    public static volatile SingularAttribute<Iban, Long> id;
    public static volatile SingularAttribute<Iban, String> country;
    public static volatile SingularAttribute<Iban, String> alpha2Code;
    public static volatile SingularAttribute<Iban, String> alpha3Code;
    public static volatile SingularAttribute<Iban, String> alphaNumeric;

    public Iban_() {
    }

}