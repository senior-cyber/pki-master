package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Arrays;
import java.util.List;

public class V021__IntermediateTable extends LiquibaseMigration {

    public V021__IntermediateTable() {
    }

    @Override
    protected List<String> getXmlChecksum() {
        return Arrays.asList("V021__IntermediateTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V021__IntermediateTable.xml");
    }

}