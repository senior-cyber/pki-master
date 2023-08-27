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
@Table(name = "tbl_user_role")
@Getter
@Setter
public class UserRole implements Serializable {

    @Id
    @Column(name = "user_role_id")
    @UuidGenerator
    @Setter(AccessLevel.NONE)
    private String id;

    @Column(name = "role_id")
    private String roleId;

    @Column(name = "user_id")
    private String userId;

}
