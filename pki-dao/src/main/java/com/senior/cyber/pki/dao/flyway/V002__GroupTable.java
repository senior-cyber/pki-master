package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class V002__GroupTable extends LiquibaseMigration {

    @Override
    protected List<String> getXmlChecksum() {
        return List.of("V002__GroupTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V002__GroupTable.xml");

        Map<String, Object> params = new HashMap<>();
        params.put("name", "Registered");
        params.put("enabled", true);
        named.update("INSERT INTO tbl_group(group_id, name, enabled) VALUES(UUID(), :name, :enabled)", params);

    }

}