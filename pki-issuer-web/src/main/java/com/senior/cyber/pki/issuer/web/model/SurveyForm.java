package com.senior.cyber.pki.issuer.web.model;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class SurveyForm implements Serializable {

    //  អត្តលេខមន្ត្រីរាជការ *
    private String civilServantIdNumber;

    //  គោត្តនាម *
    private String surName;

    // នាម *
    private String givenName;

    //  ថ្ងៃ ខែ ឆ្នាំកំណើត (DD/MM/YYYY) *
    private String dateOfBirth;

    //  លេខទូរស័ព្ទ *
    private String phoneNumber;

    // ខេត្ត / ក្រុង *
    private String province;

    //  ស្រុក / ខ័ណ្ឌ *
    private String district;

    //  ឃុំ / សង្កាត់ *
    private String commune;

    private String question1;

    private String question2;

    private String question3;

    private String question4;

    private String question5;

    private String question6;

    private String question7;

    private String question8;

    private String question9;

    private String question10;

    private String question11;

    private String question12;

}
