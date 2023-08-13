package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.*;

import java.io.Serializable;
import java.util.Map;

@Entity
@Table(name = "tbl_group")
public class Group implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "group_id")
    private Long id;

    @Column(name = "name")
    private String name;

    @Column(name = "enabled")
    private boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_group_role",
            joinColumns = @JoinColumn(name = "r_group_id", referencedColumnName = "group_id"),
            inverseJoinColumns = @JoinColumn(name = "r_role_id", referencedColumnName = "role_id")
    )
    @MapKeyColumn(name = "group_role_id")
    private Map<String, Role> roles;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "tbl_user_group",
            joinColumns = @JoinColumn(name = "r_group_id", referencedColumnName = "group_id"),
            inverseJoinColumns = @JoinColumn(name = "r_user_id", referencedColumnName = "user_id")
    )
    @MapKeyColumn(name = "user_group_id")
    private Map<String, User> users;

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Map<String, Role> getRoles() {
        return roles;
    }

    public void setRoles(Map<String, Role> roles) {
        this.roles = roles;
    }

    public Map<String, User> getUsers() {
        return users;
    }

    public void setUsers(Map<String, User> users) {
        this.users = users;
    }

}
