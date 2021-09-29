package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Arrays;
import java.util.List;

public class V010__SessionTable extends LiquibaseMigration {

    public V010__SessionTable() {
    }

    @Override
    protected List<String> getXmlChecksum() {
        return Arrays.asList("V010__SessionTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V010__SessionTable.xml");
    }

}