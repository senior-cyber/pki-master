package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(UserGroup.class)
public abstract class UserGroup_ {

    public static volatile SingularAttribute<User, String> id;
    public static volatile SingularAttribute<User, Long> groupId;
    public static volatile SingularAttribute<User, Long> userId;

}