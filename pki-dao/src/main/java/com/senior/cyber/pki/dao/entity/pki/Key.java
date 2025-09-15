package com.senior.cyber.pki.dao.entity.pki;

import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import com.senior.cyber.pki.dao.type.PublicKeyType;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;
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

    @Column(name = "private_key_pem")
    private String privateKey;

    @Convert(converter = PublicKeyType.class)
    @Column(name = "public_key_pem")
    private PublicKey publicKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "`type`")
    private KeyTypeEnum type;

    @Enumerated(EnumType.STRING)
    @Column(name = "`status`")
    private KeyStatusEnum status;

    @Enumerated(EnumType.STRING)
    @Column(name = "key_format")
    private KeyFormatEnum keyFormat;

    @Column(name = "key_size")
    private int keySize = -1;

    @Column(name = "email_address")
    private String emailAddress;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_datetime")
    private Date createdDatetime;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

}
