package com.senior.cyber.pki.dao.repository.rbac;

import com.senior.cyber.pki.dao.entity.rbac.UserGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserGroupRepository extends JpaRepository<UserGroup, String> {

    void deleteByGroupIdAndUserId(String groupId, String userId);

}
