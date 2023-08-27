package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(DenyRole.class)
public abstract class DenyRole_ {

    public static volatile SingularAttribute<DenyRole, String> id;
    public static volatile SingularAttribute<DenyRole, String> roleId;
    public static volatile SingularAttribute<DenyRole, String> userId;

}