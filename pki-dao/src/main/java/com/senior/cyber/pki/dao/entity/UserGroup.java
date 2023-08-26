package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.*;

import java.io.Serializable;
import java.util.Map;

@Entity
@Table(name = "tbl_user_group")
public class UserGroup implements Serializable {

    @Id
    @Column(name = "user_group_id")
    private String id;

    @Column(name = "r_group_id")
    private Long groupId;

    @Column(name = "r_user_id")
    private Long userId;

}
