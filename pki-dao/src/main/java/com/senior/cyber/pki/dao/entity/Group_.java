package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.MapAttribute;
import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(Group.class)
public abstract class Group_ {

    public static volatile SingularAttribute<Group, String> id;
    public static volatile SingularAttribute<Group, String> name;
    public static volatile SingularAttribute<Group, Boolean> enabled;
    public static volatile MapAttribute<Group, String, Role> roles;
    public static volatile MapAttribute<Group, String, User> users;

}