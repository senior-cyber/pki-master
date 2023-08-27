package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Entity
@Table(name = "TBL_SESSION")
@Getter
@Setter
public class Session implements Serializable {

    @Id
    @Column(name = "PRIMARY_ID")
    private String id;

    @Column(name = "SESSION_ID")
    private String sessionId;

    @Column(name = "CREATION_TIME")
    private long creationTime;

    @Column(name = "LAST_ACCESS_TIME")
    private long lastAccessTime;

    @Column(name = "MAX_INACTIVE_INTERVAL")
    private int maxInactiveInterval;

    @Column(name = "EXPIRY_TIME")
    private long expiryTime;

    @Column(name = "PRINCIPAL_NAME")
    private String principalName;

    @Column(name = "LOGIN")
    private String login;

}
