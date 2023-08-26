package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(UserRole.class)
public abstract class UserRole_ {

    public static volatile SingularAttribute<User, String> id;
    public static volatile SingularAttribute<User, Long> roleId;
    public static volatile SingularAttribute<User, Long> userId;

}