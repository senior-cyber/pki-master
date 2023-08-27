package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import com.senior.cyber.pki.dao.entity.Role;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class V004__UserRoleTable extends LiquibaseMigration {

    @Override
    protected List<String> getXmlChecksum() {
        return List.of("V004__UserRoleTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V004__UserRoleTable.xml");

        Map<String, Object> roles = new HashMap<>();
        roles.put("user", V003__UserTable.ADMIN_EMAIL);
        roles.put("role", Role.NAME_ROOT);
        roles.put("user_role_id", UUID.randomUUID().toString());
        named.update("INSERT INTO tbl_user_role(user_role_id, user_id, role_id) VALUES(:user_role_id,(SELECT user_id FROM tbl_user WHERE email_address = :user), (SELECT role_id FROM tbl_role WHERE name = :role))", roles);
    }

}