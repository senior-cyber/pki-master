package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import com.senior.cyber.pki.dao.entity.Role;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class V006__GroupRoleTable extends LiquibaseMigration {

    @Override
    protected List<String> getXmlChecksum() {
        return List.of("V006__GroupRoleTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V006__GroupRoleTable.xml");

        // Registered
        List<String> roles = List.of(
                Role.NAME_Page_MyCertificateBrowse,
                Role.NAME_Page_MyCertificateRevoke,
                Role.NAME_Page_MyCertificateGenerate,
                Role.NAME_Page_MyIntermediateBrowse,
                Role.NAME_Page_MyIntermediateRevoke,
                Role.NAME_Page_MyIntermediateGenerate,
                Role.NAME_Page_MyRootBrowse,
                Role.NAME_Page_MyRootGenerate,
                Role.NAME_Page_MyRootRevoke,
                Role.NAME_Page_MyProfile,
                Role.NAME_Page_MyKey
        );
        String group = "Registered";
        for (String role : roles) {
            Map<String, Object> params = new HashMap<>();
            params.put("group", group);
            params.put("role", role);
            params.put("group_role_id", UUID.randomUUID().toString());
            named.update("INSERT INTO tbl_group_role(group_role_id, r_group_id, r_role_id) VALUES(:group_role_id, (SELECT group_id FROM tbl_group WHERE name = :group), (SELECT role_id FROM tbl_role WHERE name = :role))", params);
        }
    }

}