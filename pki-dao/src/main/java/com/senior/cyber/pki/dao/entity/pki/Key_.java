package com.senior.cyber.pki.dao.entity.pki;

import com.senior.cyber.pki.common.x509.KeyFormat;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.KeyTypeEnum;
import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

@StaticMetamodel(Key.class)
public abstract class Key_ {

    public static volatile SingularAttribute<Key, String> id;
    public static volatile SingularAttribute<Key, PublicKey> publicKey;
    public static volatile SingularAttribute<Key, PrivateKey> privateKey;
    public static volatile SingularAttribute<Key, String> yubicoSerial;
    public static volatile SingularAttribute<Key, String> yubicoPivSlot;
    public static volatile SingularAttribute<Key, String> yubicoManagementKey;
    public static volatile SingularAttribute<Key, String> yubicoPin;
    public static volatile SingularAttribute<Key, Date> createdDatetime;
    public static volatile SingularAttribute<Key, KeyTypeEnum> type;
    public static volatile SingularAttribute<Key, String> password;
    public static volatile SingularAttribute<Key, KeyFormat> keyFormat;
    public static volatile SingularAttribute<Key, Integer> keySize;
    public static volatile SingularAttribute<Key, User> user;

}