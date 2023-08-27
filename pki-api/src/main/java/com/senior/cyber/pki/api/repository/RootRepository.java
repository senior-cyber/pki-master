package com.senior.cyber.pki.api.repository;

import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.RootStatusEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RootRepository extends JpaRepository<Root, Long> {

    Optional<Root> findBySerial(long serial);

    Optional<Root> findByIdAndUser(String id, User user);

    Optional<Root> findByCommonNameAndUserAndStatus(String commonName, User user, RootStatusEnum status);

    Optional<Root> findByOrganizationAndUserAndStatus(String organization, User user, RootStatusEnum status);

}
