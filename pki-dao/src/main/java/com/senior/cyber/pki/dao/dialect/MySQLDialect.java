package com.senior.cyber.pki.dao.dialect;

import org.hibernate.dialect.DatabaseVersion;

public class MySQLDialect extends org.hibernate.dialect.MySQLDialect {

    public MySQLDialect() {
        super(DatabaseVersion.make(8));
    }

}
