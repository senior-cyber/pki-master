package com.senior.cyber.pki.dao.entity;

import com.senior.cyber.pki.dao.type.PrivateKeyType;
import com.senior.cyber.pki.dao.type.PublicKeyType;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

@Getter
@Setter
@Entity
@Table(name = "tbl_key")
public class Key implements Serializable {

    @Id
    @UuidGenerator
    @Column(name = "key_id")
    @Setter(AccessLevel.NONE)
    private String id;

    @Convert(converter = PrivateKeyType.class)
    @Column(name = "private_key_pem")
    private PrivateKey privateKey;

    @Convert(converter = PublicKeyType.class)
    @Column(name = "public_key_pem")
    private PublicKey publicKey;

    @Column(name = "serial")
    private Long serial;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_datetime")
    private Date createdDatetime;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

}
