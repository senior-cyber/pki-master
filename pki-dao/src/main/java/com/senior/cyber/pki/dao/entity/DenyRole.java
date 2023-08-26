package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.io.Serializable;

@Entity
@Table(name = "tbl_deny_role")
public class DenyRole implements Serializable {

    @Id
    @Column(name = "deny_role_id")
    private String id;

    @Column(name = "r_role_id")
    private Long roleId;

    @Column(name = "r_user_id")
    private Long userId;

}
