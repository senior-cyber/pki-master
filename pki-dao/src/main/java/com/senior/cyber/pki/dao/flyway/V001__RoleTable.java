package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import com.senior.cyber.pki.dao.entity.Role;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class V001__RoleTable extends LiquibaseMigration {

    @Override
    protected List<String> getXmlChecksum() {
        return List.of("V001__RoleTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V001__RoleTable.xml");

        Map<String, String> roles = new LinkedHashMap<>();
        roles.put(Role.NAME_ROOT, Role.DESCRIPTION_ROOT);

        roles.put(Role.NAME_Page_MyCertificateBrowse, Role.DESCRIPTION_Page_MyCertificateBrowse);
        roles.put(Role.NAME_Page_MyCertificateBrowse_IssueNewCertificate_Action, Role.DESCRIPTION_Page_MyCertificateBrowse_IssueNewCertificate_Action);
        roles.put(Role.NAME_Page_MyCertificateBrowse_Copy_Action, Role.DESCRIPTION_Page_MyCertificateBrowse_Copy_Action);
        roles.put(Role.NAME_Page_MyCertificateBrowse_Revoke_Action, Role.DESCRIPTION_Page_MyCertificateBrowse_Revoke_Action);
        roles.put(Role.NAME_Page_MyCertificateBrowse_Download_Action, Role.DESCRIPTION_Page_MyCertificateBrowse_Download_Action);

        roles.put(Role.NAME_Page_MyCertificateGenerate, Role.DESCRIPTION_Page_MyCertificateGenerate);
        roles.put(Role.NAME_Page_MyCertificateGenerate_Issue_Action, Role.DESCRIPTION_Page_MyCertificateGenerate_Issue_Action);

        roles.put(Role.NAME_Page_MyCertificateRevoke, Role.DESCRIPTION_Page_MyCertificateRevoke);
        roles.put(Role.NAME_Page_MyCertificateRevoke_Revoke_Action, Role.DESCRIPTION_Page_MyCertificateRevoke_Revoke_Action);

        roles.put(Role.NAME_Page_MyIntermediateBrowse, Role.DESCRIPTION_Page_MyIntermediateBrowse);
        roles.put(Role.NAME_Page_MyIntermediateBrowse_IssueNewIntermediate_Action, Role.DESCRIPTION_Page_MyIntermediateBrowse_IssueNewIntermediate_Action);
        roles.put(Role.NAME_Page_MyIntermediateBrowse_Copy_Action, Role.DESCRIPTION_Page_MyIntermediateBrowse_Copy_Action);
        roles.put(Role.NAME_Page_MyIntermediateBrowse_Download_Action, Role.DESCRIPTION_Page_MyIntermediateBrowse_Download_Action);
        roles.put(Role.NAME_Page_MyIntermediateBrowse_Revoke_Action, Role.DESCRIPTION_Page_MyIntermediateBrowse_Revoke_Action);

        roles.put(Role.NAME_Page_MyIntermediateGenerate, Role.DESCRIPTION_Page_MyIntermediateGenerate);
        roles.put(Role.NAME_Page_MyIntermediateGenerate_Issue_Action, Role.DESCRIPTION_Page_MyIntermediateGenerate_Issue_Action);

        roles.put(Role.NAME_Page_CsrSubmit, Role.DESCRIPTION_Page_CsrGenerate);

        roles.put(Role.NAME_Page_CsrGenerate, Role.DESCRIPTION_Page_CsrSubmit);

        roles.put(Role.NAME_Page_MyIntermediateRevoke, Role.DESCRIPTION_Page_MyIntermediateRevoke);
        roles.put(Role.NAME_Page_MyIntermediateRevoke_Revoke_Action, Role.DESCRIPTION_Page_MyIntermediateRevoke_Revoke_Action);

        roles.put(Role.NAME_Page_MyRootBrowse, Role.DESCRIPTION_Page_MyRootBrowse);
        roles.put(Role.NAME_Page_MyRootBrowse_IssueNewRoot_Action, Role.DESCRIPTION_Page_MyRootBrowse_IssueNewRoot_Action);
        roles.put(Role.NAME_Page_MyRootBrowse_Copy_Action, Role.DESCRIPTION_Page_MyRootBrowse_Copy_Action);
        roles.put(Role.NAME_Page_MyRootBrowse_Download_Action, Role.DESCRIPTION_Page_MyRootBrowse_Download_Action);
        roles.put(Role.NAME_Page_MyRootBrowse_Revoke_Action, Role.DESCRIPTION_Page_MyRootBrowse_Revoke_Action);

        roles.put(Role.NAME_Page_MyRootGenerate, Role.DESCRIPTION_Page_MyRootGenerate);
        roles.put(Role.NAME_Page_MyRootGenerate_Issue_Action, Role.DESCRIPTION_Page_MyRootGenerate_Issue_Action);

        roles.put(Role.NAME_Page_MyRootRevoke, Role.DESCRIPTION_Page_MyRootRevoke);
        roles.put(Role.NAME_Page_MyRootRevoke_Revoke_Action, Role.DESCRIPTION_Page_MyRootRevoke_Revoke_Action);

        roles.put(Role.NAME_Page_MyProfile, Role.DESCRIPTION_Page_MyProfile);

        roles.put(Role.NAME_Page_MyKey, Role.DESCRIPTION_Page_MyKey);
        roles.put(Role.NAME_Page_MyKey_Create_Action, Role.DESCRIPTION_Page_MyKey_Create_Action);
        roles.put(Role.NAME_Page_MyKey_Delete_Action, Role.DESCRIPTION_Page_MyKey_Delete_Action);
        roles.put(Role.NAME_Page_MyKey_ShowSecret_Action, Role.DESCRIPTION_Page_MyKey_ShowSecret_Action);

        roles.put(Role.NAME_Page_SessionBrowse, Role.DESCRIPTION_Page_SessionBrowse);
        roles.put(Role.NAME_Page_SessionBrowse_Revoke_Action, Role.DESCRIPTION_Page_SessionBrowse_Revoke_Action);

        roles.put(Role.NAME_Page_RoleBrowse, Role.DESCRIPTION_Page_RoleBrowse);
        roles.put(Role.NAME_Page_GroupBrowse, Role.DESCRIPTION_Page_GroupBrowse);
        roles.put(Role.NAME_Page_GroupModify, Role.DESCRIPTION_Page_GroupModify);
        roles.put(Role.NAME_Page_UserBrowse, Role.DESCRIPTION_Page_UserBrowse);
        roles.put(Role.NAME_Page_UserModify, Role.DESCRIPTION_Page_UserModify);
        roles.put(Role.NAME_Page_UserSwitch, Role.DESCRIPTION_Page_UserSwitch);
        roles.put(Role.NAME_Page_UserExit, Role.DESCRIPTION_Page_UserExit);

        String insert = "INSERT INTO tbl_role(role_id, name, description, enabled) VALUES(UUID(), :name, :description, true)";
        for (Map.Entry<String, String> role : roles.entrySet()) {
            Map<String, Object> params = new HashMap<>();
            params.put("name", role.getKey());
            params.put("description", role.getValue());
            named.update(insert, params);
        }
    }

}