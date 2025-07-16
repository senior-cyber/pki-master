package com.senior.cyber.pki.common.x509;

public enum YubicoPivSlotEnum {
    _9A("9a", "Certificate for PIV Authentication"),
    _9C("9c", "Certificate for Digital Signature"),
    _9D("9d", "Certificate for Key Management"),
    _9E("9e", "Certificate for Card Authentication");

    private final String alias;

    private final String slotName;

    YubicoPivSlotEnum(String slotName, String alias) {
        this.slotName = slotName;
        this.alias = alias;
    }

    public String getAlias() {
        return alias;
    }

    public String getSlotName() {
        return slotName;
    }

}
