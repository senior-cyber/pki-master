package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Arrays;
import java.util.List;

public class V020__RootTable extends LiquibaseMigration {

    public V020__RootTable() {
    }

    @Override
    protected List<String> getXmlChecksum() {
        return Arrays.asList("V020__RootTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V020__RootTable.xml");
    }

}