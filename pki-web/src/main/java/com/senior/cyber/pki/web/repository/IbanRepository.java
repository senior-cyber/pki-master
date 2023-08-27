package com.senior.cyber.pki.web.repository;

import com.senior.cyber.pki.dao.entity.Iban;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IbanRepository extends JpaRepository<Iban, String> {

    Optional<Iban> findByAlpha2Code(String alpha2Code);

}
