package com.senior.cyber.pki.dao.entity.pki;

import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
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

    @Enumerated(EnumType.STRING)
    @Column(name = "type")
    private KeyTypeEnum type;

    @Enumerated(EnumType.STRING)
    @Column(name = "key_format")
    private KeyFormat keyFormat;

    @Column(name = "key_size")
    private int keySize = -1;

    @Column(name = "pwd")
    private String password;

    @Column(name = "yubico_serial")
    private String yubicoSerial;

    @Column(name = "yubico_piv_slot")
    private String yubicoPivSlot;

    @Column(name = "yubico_management_key")
    private String yubicoManagementKey;

    @Column(name = "yubico_pin")
    private String yubicoPin;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_datetime")
    private Date createdDatetime;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

}
