package com.senior.cyber.pki.dao.repository.rbac;

import com.senior.cyber.pki.dao.entity.rbac.Group;
import com.senior.cyber.pki.dao.entity.rbac.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface GroupRepository extends JpaRepository<Group, String> {

    List<Group> findAllByNameStartsWith(String name);

    long countByName(String name);

    long countByNameAndIdNot(String name, String id);

    @Query("SELECT g FROM Group g JOIN g.users u WHERE u = :user")
    Page<Group> findAllByUser(@Param("user") User user, Pageable pageable);

}
