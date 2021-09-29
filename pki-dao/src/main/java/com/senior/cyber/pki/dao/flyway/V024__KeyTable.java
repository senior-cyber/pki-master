package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Arrays;
import java.util.List;

public class V024__KeyTable extends LiquibaseMigration {

    public V024__KeyTable() {
    }

    @Override
    protected List<String> getXmlChecksum() {
        return Arrays.asList("V024__KeyTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V024__KeyTable.xml");
    }

}