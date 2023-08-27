package com.senior.cyber.pki.web.repository;

import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.IntermediateStatusEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IntermediateRepository extends JpaRepository<Intermediate, String> {

    Optional<Intermediate> findBySerial(long serial);

    Optional<Intermediate> findByIdAndUser(String id, User user);

    Optional<Intermediate> findBySerialAndRoot(long serial, Root root);

    List<Intermediate> findByRoot(Root root);

    List<Intermediate> findByRootAndStatus(Root root, IntermediateStatusEnum status);

    Optional<Intermediate> findByCommonNameAndStatus(String commonName, IntermediateStatusEnum status);

    Optional<Intermediate> findByCommonNameAndUserAndStatus(String commonName, User user, IntermediateStatusEnum status);

    Optional<Intermediate> findByOrganizationAndStatus(String organization, IntermediateStatusEnum status);

    Optional<Intermediate> findByOrganizationAndUserAndStatus(String organization, User user, IntermediateStatusEnum status);

}
