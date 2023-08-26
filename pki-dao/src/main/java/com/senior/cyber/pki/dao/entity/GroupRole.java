package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.io.Serializable;

@Entity
@Table(name = "tbl_group_role")
public class GroupRole implements Serializable {

    @Id
    @Column(name = "group_role_id")
    private String id;

    @Column(name = "r_group_id")
    private Long groupId;

    @Column(name = "r_role_id")
    private Long roleId;

}