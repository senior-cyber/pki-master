package com.senior.cyber.pki.common.x509;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class SubjectUtils {

    public static X500Name generate(String countryCode,
                                    String organization,
                                    String organizationalUnit,
                                    String commonName,
                                    String localityName,
                                    String stateOrProvinceName,
                                    String emailAddress) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (countryCode != null && !countryCode.isEmpty()) {
            builder.addRDN(BCStyle.C, countryCode);
        }
        if (organization != null && !organization.isEmpty()) {
            builder.addRDN(BCStyle.O, organization);
        }
        if (organizationalUnit != null && !organizationalUnit.isEmpty()) {
            builder.addRDN(BCStyle.OU, organizationalUnit);
        }
        if (commonName != null && !commonName.isEmpty()) {
            builder.addRDN(BCStyle.CN, commonName);
        }
        if (localityName != null && !localityName.isEmpty()) {
            builder.addRDN(BCStyle.L, localityName);
        }
        if (stateOrProvinceName != null && !stateOrProvinceName.isEmpty()) {
            builder.addRDN(BCStyle.ST, stateOrProvinceName);
        }
        if (emailAddress != null && !emailAddress.isEmpty()) {
            builder.addRDN(BCStyle.EmailAddress, emailAddress);
        }

        // builder.addRDN(BCStyle.T, "Position");
        // builder.addRDN(BCStyle.STREET, "Address");
        // builder.addRDN(BCStyle.SERIALNUMBER, "Serial Number");
        // builder.addRDN(BCStyle.SURNAME, "Sur Name");
        // builder.addRDN(BCStyle.GIVENNAME, "Given Name");
        // builder.addRDN(BCStyle.INITIALS, "Mr./Mrs./Miss.");
        // builder.addRDN(BCStyle.DESCRIPTION, "Description");
        // builder.addRDN(BCStyle.POSTAL_CODE, "Postal Code");
        // builder.addRDN(BCStyle.TELEPHONE_NUMBER, "Telephone Number");

        return builder.build();
    }

}
