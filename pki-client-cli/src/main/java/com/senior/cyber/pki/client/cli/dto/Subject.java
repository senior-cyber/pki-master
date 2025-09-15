package com.senior.cyber.pki.client.cli.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.List;

@Setter
@Getter
public class Subject implements Serializable {

    @JsonProperty("l")
    private String locality;

    @JsonProperty("st")
    private String province;

    @JsonProperty("c")
    private String country;

    @JsonProperty("cn")
    private String commonName;

    @JsonProperty("o")
    private String organization;

    @JsonProperty("ou")
    private String organizationalUnit;

    @JsonProperty("emailAddress")
    private String emailAddress;

    @JsonProperty("sans")
    private List<String> sans;

}
