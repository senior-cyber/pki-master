package com.senior.cyber.pki.web.utility;

import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Collections;
import java.util.List;

public class RoleUtility {

    public static List<String> lookupRole(NamedParameterJdbcTemplate named, long userId) {
        String deniedQuery = "SELECT r.role_id FROM tbl_role r INNER JOIN tbl_deny_role ud ON r.role_id = ud.r_role_id WHERE ud.r_user_id = " + userId + " AND r.enabled = true";
        String userQuery = "SELECT r.name FROM tbl_role r INNER JOIN tbl_user_role ur ON r.role_id = ur.r_role_id WHERE ur.r_user_id = " + userId + " AND r.enabled = true and r.role_id NOT IN (" + deniedQuery + ")";
        String groupQuery = "SELECT r.name FROM tbl_role r INNER JOIN tbl_group_role gr ON r.role_id = gr.r_role_id INNER JOIN tbl_user_group ug ON gr.r_group_id = ug.r_group_id WHERE ug.r_user_id = " + userId + " AND r.enabled = true AND r.role_id NOT IN (" + deniedQuery + ")";
        return named.queryForList(userQuery + " UNION " + groupQuery, Collections.emptyMap(), String.class);
    }

}
