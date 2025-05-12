package com.senior.cyber.pki.dao.repository.rbac;

import com.senior.cyber.pki.dao.entity.rbac.Group;
import com.senior.cyber.pki.dao.entity.rbac.Role;
import com.senior.cyber.pki.dao.entity.rbac.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleRepository extends JpaRepository<Role, String> {

    List<Role> findAllByNameStartsWith(String name);

    @Query("SELECT r FROM Role r JOIN r.users u WHERE u = :user")
    List<Role> findAllByUser(@Param("user") User user);

    @Query("SELECT r FROM Role r JOIN r.users u WHERE u = :user")
    Page<Role> findAllByUser(@Param("user") User user, Pageable pageable);

    @Query("SELECT r FROM Role r JOIN r.denyUsers u WHERE u = :denyUser")
    Page<Role> findAllByDenyUser(@Param("denyUser") User denyUser, Pageable pageable);

    @Query("SELECT r FROM Role r JOIN r.groups g WHERE g = :group")
    Page<Role> findAllByGroup(@Param("group") Group group, Pageable pageable);

    long countByName(String name);

    long countByNameAndIdNot(String name, String id);

}
