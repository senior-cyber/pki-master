package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;

@Entity
@Table(name = "tbl_group_role")
@Getter
@Setter
public class GroupRole implements Serializable {

    @Id
    @Column(name = "group_role_id")
    @UuidGenerator
    @Setter(AccessLevel.NONE)
    private String id;

    @Column(name = "group_id")
    private String groupId;

    @Column(name = "role_id")
    private String roleId;

}