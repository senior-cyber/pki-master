package com.senior.cyber.pki.dao.entity.rbac;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;

@Getter
@Setter
@Entity
@Table(name = "tbl_rbac_user")
public class User implements Serializable {

    // RBAC

    @Id
    @UuidGenerator
    @Column(name = "user_id")
    @Setter(AccessLevel.NONE)
    private String id;

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "enabled")
    private boolean enabled;

    @Column(name = "login")
    private String login;

    @Column(name = "pwd")
    private String password;

    @Column(name = "email_address")
    private String emailAddress;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "last_seen")
    private Date lastSeen;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_rbac_user_group",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "group_id", referencedColumnName = "group_id")

    )
    @MapKeyColumn(name = "user_group_id")
    private Map<String, Group> groups;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_rbac_user_role",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id")

    )
    @MapKeyColumn(name = "user_role_id")
    private Map<String, Role> roles;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_rbac_deny_role",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id")
    )
    @MapKeyColumn(name = "deny_role_id")
    private Map<String, Role> denyRoles;

}
