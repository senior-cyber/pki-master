package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.jackson.Jacksonized;

import java.io.Serializable;

@Setter
@Getter
@Jacksonized
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class RootGenerateRequest implements Serializable {

    @JsonProperty("key")
    private Key key;

    @JsonProperty("subject")
    private Subject subject;

}
