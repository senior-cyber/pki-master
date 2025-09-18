package com.senior.cyber.pki.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@Builder
public class QueueSearchResponse extends BaseRequest {

    @JsonProperty("queues")
    private List<Queue> queues;

    @JsonCreator
    public static QueueSearchResponse create() {
        return QueueSearchResponse.builder().build();
    }

}
