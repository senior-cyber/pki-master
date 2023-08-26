package com.senior.cyber.pki.web.utility;

import com.senior.cyber.frmk.common.jpa.Sql;
import com.senior.cyber.pki.dao.entity.*;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Collections;
import java.util.List;

public class RoleUtility {

    public static List<String> lookupRole(NamedParameterJdbcTemplate named, long userId) {
        String deniedQuery = "SELECT " + Sql.column(Role_.id) + " FROM " + Sql.table(Role_.class) + " INNER JOIN " + Sql.table(DenyRole_.class) + " ON " + Sql.column(DenyRole_.roleId) + " = " + Sql.column(Role_.id) + " WHERE " + Sql.column(DenyRole_.userId) + " = " + userId + " AND " + Sql.column(Role_.enabled) + " = true";
        String userQuery = "SELECT " + Sql.column(Role_.name) + " FROM " + Sql.table(Role_.class) + " INNER JOIN " + Sql.table(UserRole_.class) + " ON " + Sql.column(UserRole_.roleId) + " = " + Sql.column(Role_.id) + " WHERE " + Sql.column(UserRole_.roleId) + " = " + userId + " AND " + Sql.column(Role_.enabled) + " = true AND " + Sql.column(Role_.id) + " NOT IN (" + deniedQuery + ")";
        String groupQuery = "SELECT " + Sql.column(Role_.name) + " FROM " + Sql.table(Role_.class) + " INNER JOIN " + Sql.table(GroupRole_.class) + " ON " + Sql.column(GroupRole_.roleId) + " = " + Sql.column(Role_.id) + " INNER JOIN " + Sql.table(UserGroup_.class) + " ON " + Sql.column(UserGroup_.groupId) + " = " + Sql.column(GroupRole_.groupId) + " WHERE " + Sql.column(UserGroup_.userId) + " = " + userId + " AND " + Sql.column(Role_.enabled) + " = true AND " + Sql.column(Role_.id) + " NOT IN (" + deniedQuery + ")";
        String query = userQuery + " UNION " + groupQuery;
        return named.queryForList(query, Collections.emptyMap(), String.class);
    }

}
