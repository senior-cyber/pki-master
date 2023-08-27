package com.senior.cyber.pki.web.repository;

import com.senior.cyber.pki.dao.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface GroupRepository extends JpaRepository<Group, String> {

    Optional<Group> findByName(String name);

}
