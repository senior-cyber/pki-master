package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.io.Serializable;

@Entity
@Table(name = "TBL_SESSION")
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

    public String getId() {
        return id;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public long getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(long creationTime) {
        this.creationTime = creationTime;
    }

    public long getLastAccessTime() {
        return lastAccessTime;
    }

    public void setLastAccessTime(long lastAccessTime) {
        this.lastAccessTime = lastAccessTime;
    }

    public int getMaxInactiveInterval() {
        return maxInactiveInterval;
    }

    public void setMaxInactiveInterval(int maxInactiveInterval) {
        this.maxInactiveInterval = maxInactiveInterval;
    }

    public long getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {
        this.expiryTime = expiryTime;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }
}
