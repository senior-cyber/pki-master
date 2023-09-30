package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.frmk.jdbc.query.InsertQuery;
import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class V003__UserTable extends LiquibaseMigration {

    public static final String ADMIN_EMAIL = "senior.cyber@gmail.com";

    @Override
    protected List<String> getXmlChecksum() {
        return List.of("V003__UserTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V003__UserTable.xml");

        StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();

        InsertQuery insertQuery = null;
        insertQuery = new InsertQuery("tbl_user");
        insertQuery.addValue("user_id", ":user_id", Map.of("user_id", UUID.randomUUID().toString()));
        insertQuery.addValue("display_name", ":display_name", Map.of("display_name", "Senior Cyber"));
        insertQuery.addValue("enabled", ":enabled", Map.of("enabled", true));
        insertQuery.addValue("login", ":login", Map.of("login", "admin"));
        insertQuery.addValue("pwd", ":pwd", Map.of("pwd", passwordEncryptor.encryptPassword("admin")));
        insertQuery.addValue("email_address", ":email_address", Map.of("email_address", ADMIN_EMAIL));
        insertQuery.addValue("last_seen", ":last_seen", Map.of("last_seen", new Date()));
        named.update(insertQuery.toSQL(), insertQuery.toParam());
    }

}