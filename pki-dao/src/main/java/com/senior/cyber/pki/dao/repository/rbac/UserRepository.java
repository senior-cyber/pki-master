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
public interface UserRepository extends JpaRepository<User, String> {

    User findByLogin(String login);

    User findByEmailAddress(String emailAddress);

    boolean existsByLogin(String login);

    long countByLogin(String login);

    long countByEmailAddress(String emailAddress);

    List<User> findAllByLoginStartsWith(String login);

    @Query("SELECT u FROM User u JOIN u.groups g WHERE g = :group")
    Page<User> findAllByGroup(@Param("group") Group group, Pageable pageable);

    long countByLoginAndIdNot(String login, String id);

    long countByEmailAddressAndIdNot(String emailAddress, String id);
}
