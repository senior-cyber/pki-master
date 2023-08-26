package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(GroupRole.class)
public abstract class GroupRole_ {

    public static volatile SingularAttribute<User, String> id;
    public static volatile SingularAttribute<User, Long> groupId;
    public static volatile SingularAttribute<User, Long> roleId;

}