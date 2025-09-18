package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class QueueSearchRequest extends BaseRequest {

    @JsonProperty("keyId")
    private String keyId;

    @JsonCreator
    public static QueueSearchRequest create() {
        return QueueSearchRequest.builder().build();
    }

}
