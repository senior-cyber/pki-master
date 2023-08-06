package com.senior.cyber.pki.dao;

import com.senior.cyber.frmk.metamodel.LiquibaseJavaMigration;

public abstract class LiquibaseMigration extends LiquibaseJavaMigration {

    public LiquibaseMigration() {
        super("/liquibase_output/");
    }

}
