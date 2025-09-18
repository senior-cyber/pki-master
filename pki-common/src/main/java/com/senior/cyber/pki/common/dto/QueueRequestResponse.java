package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class QueueRequestResponse extends BaseRequest {

    @JsonProperty("queueId")
    private String queueId;

    @JsonCreator
    public static QueueRequestResponse create() {
        return QueueRequestResponse.builder().build();
    }

}
