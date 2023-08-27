package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;

@Entity
@Table(name = "tbl_key")
@Getter
@Setter
public class Key implements Serializable {

    @Id
    @UuidGenerator
    @Column(name = "key_id")
    @Setter(AccessLevel.NONE)
    private String id;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "kek")
    private String kek;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

}
