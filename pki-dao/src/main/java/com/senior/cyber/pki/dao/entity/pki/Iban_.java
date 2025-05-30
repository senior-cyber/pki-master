package com.senior.cyber.pki.dao.entity.pki;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(Iban.class)
public abstract class Iban_ {

    public static volatile SingularAttribute<Iban, String> id;
    public static volatile SingularAttribute<Iban, String> country;
    public static volatile SingularAttribute<Iban, String> alpha2Code;
    public static volatile SingularAttribute<Iban, String> alpha3Code;
    public static volatile SingularAttribute<Iban, String> alphaNumeric;

}