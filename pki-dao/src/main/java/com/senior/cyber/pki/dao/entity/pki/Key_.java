package com.senior.cyber.pki.dao.entity.pki;

import com.senior.cyber.pki.common.x509.KeyFormatEnum;
import com.senior.cyber.pki.dao.entity.rbac.User;
import com.senior.cyber.pki.dao.enums.KeyStatusEnum;
import com.senior.cyber.pki.common.x509.KeyTypeEnum;
import jakarta.persistence.metamodel.SingularAttribute;
import jakarta.persistence.metamodel.StaticMetamodel;

import java.security.PublicKey;
import java.util.Date;

@StaticMetamodel(Key.class)
public abstract class Key_ {

    public static volatile SingularAttribute<Key, String> id;
    public static volatile SingularAttribute<Key, PublicKey> publicKey;
    public static volatile SingularAttribute<Key, String> privateKey;
    public static volatile SingularAttribute<Key, Date> createdDatetime;
    public static volatile SingularAttribute<Key, KeyTypeEnum> type;
    public static volatile SingularAttribute<Key, KeyStatusEnum> status;
    public static volatile SingularAttribute<Key, KeyFormatEnum> keyFormat;
    public static volatile SingularAttribute<Key, Integer> keySize;
    public static volatile SingularAttribute<Key, User> user;

}