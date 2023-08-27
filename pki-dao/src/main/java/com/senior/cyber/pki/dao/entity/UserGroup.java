package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.util.Map;

@Entity
@Table(name = "tbl_user_group")
@Getter
@Setter
public class UserGroup implements Serializable {

    @Id
    @Column(name = "user_group_id")
    @Setter(AccessLevel.NONE)
    @UuidGenerator
    private String id;

    @Column(name = "group_id")
    private String groupId;

    @Column(name = "user_id")
    private String userId;

}
