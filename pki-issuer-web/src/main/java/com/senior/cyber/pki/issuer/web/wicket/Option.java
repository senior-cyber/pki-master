package com.senior.cyber.pki.issuer.web.wicket;

import java.io.Serializable;

public class Option implements Serializable {

    private String idValue;

    private String displayValue;

    public Option(String idValue, String displayValue) {
        this.idValue = idValue;
        this.displayValue = displayValue;
    }

    public String getDisplayValue() {
        return displayValue;
    }

    public void setDisplayValue(String displayValue) {
        this.displayValue = displayValue;
    }

    public String getIdValue() {
        return idValue;
    }

    public void setIdValue(String idValue) {
        this.idValue = idValue;
    }

}
