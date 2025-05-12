package com.senior.cyber.pki.dao.repository.rbac;

import com.senior.cyber.pki.dao.entity.rbac.GroupRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GroupRoleRepository extends JpaRepository<GroupRole, String> {

    void deleteByGroupIdAndRoleId(String groupId, String roleId);

}
