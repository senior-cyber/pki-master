package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(Session.class)
public abstract class Session_ {

    public static volatile SingularAttribute<Session, String> id;
    public static volatile SingularAttribute<Session, String> sessionId;
    public static volatile SingularAttribute<Session, Long> creationTime;
    public static volatile SingularAttribute<Session, Long> lastAccessTime;
    public static volatile SingularAttribute<Session, Integer> maxInactiveInterval;
    public static volatile SingularAttribute<Session, Long> expiryTime;
    public static volatile SingularAttribute<Session, String> principalName;
    public static volatile SingularAttribute<Session, String> login;

}