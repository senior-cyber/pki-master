package com.senior.cyber.pki.dao.entity.rbac;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.util.Map;

@Getter
@Setter
@Entity
@Table(name = "tbl_rbac_role")
public class Role implements Serializable {

    @Id
    @UuidGenerator
    @Setter(AccessLevel.NONE)
    @Column(name = "role_id")
    private String id;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "enabled")
    private boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_rbac_group_role",
            joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "group_id", referencedColumnName = "group_id")

    )
    @MapKeyColumn(name = "group_role_id")
    private Map<String, Group> groups;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_rbac_user_role",
            joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id", referencedColumnName = "user_id")

    )
    @MapKeyColumn(name = "user_role_id")
    private Map<String, User> users;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_rbac_deny_role",
            joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    )
    @MapKeyColumn(name = "deny_role_id")
    private Map<String, User> denyUsers;

}
