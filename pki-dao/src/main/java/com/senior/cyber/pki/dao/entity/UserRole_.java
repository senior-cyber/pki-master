package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(UserRole.class)
public abstract class UserRole_ {

    public static volatile SingularAttribute<UserRole, String> id;
    public static volatile SingularAttribute<UserRole, String> roleId;
    public static volatile SingularAttribute<UserRole, String> userId;

}