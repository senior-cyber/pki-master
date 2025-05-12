package com.senior.cyber.pki.dao.entity.rbac;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(GroupRole.class)
public abstract class GroupRole_ {

    public static volatile SingularAttribute<GroupRole, String> id;
    public static volatile SingularAttribute<GroupRole, String> groupId;
    public static volatile SingularAttribute<GroupRole, String> roleId;

}