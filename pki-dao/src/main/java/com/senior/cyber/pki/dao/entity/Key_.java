package com.senior.cyber.pki.dao.entity;

import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(Key.class)
public abstract class Key_ {

    public static volatile SingularAttribute<Key, Long> id;
    public static volatile SingularAttribute<Key, String> clientId;
    public static volatile SingularAttribute<Key, String> clientSecret;
    public static volatile SingularAttribute<Key, String> kek;
    public static volatile SingularAttribute<Key, User> user;

    public Key_() {
    }

}