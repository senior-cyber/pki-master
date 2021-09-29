package com.senior.cyber.pki.dao.entity;

import javax.persistence.metamodel.MapAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(Role.class)
public abstract class Role_ {

    public static volatile SingularAttribute<Role, Long> id;
    public static volatile SingularAttribute<Role, String> name;
    public static volatile SingularAttribute<Role, String> description;
    public static volatile SingularAttribute<Role, Boolean> enabled;
    public static volatile MapAttribute<Role, String, Group> groups;
    public static volatile MapAttribute<Role, String, User> users;
    public static volatile MapAttribute<Role, String, User> denyUsers;

    public Role_() {
    }

}