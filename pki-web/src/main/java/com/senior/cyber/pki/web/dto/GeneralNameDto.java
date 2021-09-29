package com.senior.cyber.pki.web.dto;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.bouncycastle.asn1.x509.GeneralName;

public class GeneralNameDto {

    @Expose
    @SerializedName("type")
    private GeneralNameTypeEnum type;

    @Expose
    @SerializedName("tag")
    private int tag;

    @Expose
    @SerializedName("name")
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
