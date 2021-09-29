package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Arrays;
import java.util.List;

public class V022__CertificateTable extends LiquibaseMigration {

    public V022__CertificateTable() {
    }

    @Override
    protected List<String> getXmlChecksum() {
        return Arrays.asList("V022__CertificateTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V022__CertificateTable.xml");
    }

}