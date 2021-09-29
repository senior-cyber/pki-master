package com.senior.cyber.pki.dao.entity;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "tbl_iban")
public class Iban implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "iban_id")
    private Long id;

    @Column(name = "country")
    private String country;

    @Column(name = "alpha2_code")
    private String alpha2Code;

    @Column(name = "alpha3_code")
    private String alpha3Code;

    @Column(name = "alpha_numeric")
    private String alphaNumeric;

    public Long getId() {
        return id;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getAlpha2Code() {
        return alpha2Code;
    }

    public void setAlpha2Code(String alpha2Code) {
        this.alpha2Code = alpha2Code;
    }

    public String getAlpha3Code() {
        return alpha3Code;
    }

    public void setAlpha3Code(String alpha3Code) {
        this.alpha3Code = alpha3Code;
    }

    public String getAlphaNumeric() {
        return alphaNumeric;
    }

    public void setAlphaNumeric(String alphaNumeric) {
        this.alphaNumeric = alphaNumeric;
    }

}
