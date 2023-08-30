package com.senior.cyber.pki.root.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.bouncycastle.asn1.x509.GeneralName;

public class GeneralNameDto {

    @JsonProperty("type")
    private GeneralNameTypeEnum type;

    @JsonProperty("tag")
    private int tag;

    @JsonProperty("name")
    private String name;

    public GeneralNameDto() {
    }

    public GeneralNameDto(String name) {
        this.tag = GeneralName.uniformResourceIdentifier;
        this.name = name;
    }

    public GeneralNameDto(GeneralNameTagEnum tag, String name) {
        if (GeneralNameTagEnum.IP == tag) {
            this.tag = GeneralName.iPAddress;
        } else if (GeneralNameTagEnum.DNS == tag) {
            this.tag = GeneralName.dNSName;
        }
        this.name = name;
    }

    public GeneralNameDto(GeneralNameTypeEnum type, String name) {
        this.type = type;
        this.tag = GeneralName.uniformResourceIdentifier;
        this.name = name;
    }

    public GeneralNameTypeEnum getType() {
        return type;
    }

    public int getTag() {
        return tag;
    }

    public String getName() {
        return name;
    }

}
