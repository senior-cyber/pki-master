package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Arrays;
import java.util.List;

public class V021__KeyTable extends LiquibaseMigration {

    public V021__KeyTable() {
    }

    @Override
    protected List<String> getXmlChecksum() {
        return Arrays.asList("V021__KeyTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V021__KeyTable.xml");
    }

}