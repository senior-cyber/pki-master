package com.senior.cyber.pki.dao.entity.cluster;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;

@Getter
@Setter
@Entity
@Table(name = "tbl_cluster_SPRING_SESSION")
public class HttpSession implements Serializable {

    @Id
    @UuidGenerator
    @Column(name = "PRIMARY_ID")
    @Setter(AccessLevel.NONE)
    private String id;

    @Column(name = "SESSION_ID")
    private String sessionId;

    @Column(name = "CREATION_TIME")
    private Long creationTime;

    @Column(name = "LAST_ACCESS_TIME")
    private Long lastAccessTime;

    @Column(name = "MAX_INACTIVE_INTERVAL")
    private Long maxInactiveInterval;

    @Column(name = "EXPIRY_TIME")
    private Long expiryTime;

    @Column(name = "PRINCIPAL_NAME")
    private String principalName;

    public String getCreationTimeText() {
        if (this.creationTime == null) {
            return "";
        } else {
            return DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(this.creationTime);
        }
    }

    public String getLastAccessTimeText() {
        if (this.lastAccessTime == null) {
            return "";
        } else {
            return DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(this.lastAccessTime);
        }
    }

    public String getExpiryTimeText() {
        if (this.expiryTime == null) {
            return "";
        } else {
            return DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(this.expiryTime);
        }
    }

    public String getMaxInactiveIntervalText() {
        if (this.maxInactiveInterval == null) {
            return "";
        } else {
            return DurationFormatUtils.formatDurationISO(this.maxInactiveInterval);
        }
    }

}
