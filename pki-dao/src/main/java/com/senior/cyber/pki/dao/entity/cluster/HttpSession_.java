package com.senior.cyber.pki.dao.entity.cluster;

import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

@StaticMetamodel(HttpSession.class)
public abstract class HttpSession_ {

    public static volatile SingularAttribute<HttpSession, String> id;
    public static volatile SingularAttribute<HttpSession, String> sessionId;
    public static volatile SingularAttribute<HttpSession, String> principalName;
    public static volatile SingularAttribute<HttpSession, Long> expiryTime;
    public static volatile SingularAttribute<HttpSession, Long> creationTime;
    public static volatile SingularAttribute<HttpSession, Long> lastAccessTime;
    public static volatile SingularAttribute<HttpSession, Long> maxInactiveInterval;

}