package com.senior.cyber.pki.dao.repository.pki;

import com.senior.cyber.pki.dao.entity.pki.Iban;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IbanRepository extends JpaRepository<Iban, String> {

    Iban findByAlpha2Code(String alpha2Code);

}
