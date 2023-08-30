package com.senior.cyber.pki.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;

import java.io.Serializable;

@Entity
@Table(name = "tbl_iban")
@Getter
@Setter
public class Iban implements Serializable {

    @Id
    @UuidGenerator
    @Column(name = "iban_id")
    @Setter(AccessLevel.NONE)
    private String id;

    @Column(name = "country")
    private String country;

    @Column(name = "alpha2_code")
    private String alpha2Code;

    @Column(name = "alpha3_code")
    private String alpha3Code;

    @Column(name = "alpha_numeric")
    private String alphaNumeric;

}
