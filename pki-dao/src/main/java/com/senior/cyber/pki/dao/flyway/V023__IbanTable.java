package com.senior.cyber.pki.dao.flyway;

import com.senior.cyber.pki.dao.LiquibaseMigration;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class V023__IbanTable extends LiquibaseMigration {

    public V023__IbanTable() {
    }

    @Override
    protected List<String> getXmlChecksum() {
        return Arrays.asList("V023__IbanTable.xml");
    }

    @Override
    protected void doMigrate(NamedParameterJdbcTemplate named) throws Exception {
        updateLiquibase("V023__IbanTable.xml");
        NumberFormat format = new DecimalFormat("000");
        try (InputStream stream = V023__IbanTable.class.getResourceAsStream("/csv/iban.csv")) {
            Iterable<CSVRecord> records = CSVFormat.RFC4180.parse(new InputStreamReader(stream));
            for (CSVRecord record : records) {
                String country = record.get(0);
                String alpha2Code = record.get(1);
                String alpha3Code = record.get(2);
                String alphaNumeric = format.format(Long.parseLong(record.get(3)));
                Map<String, Object> params = new HashMap<>();
                params.put("country", country);
                params.put("alpha2_code", alpha2Code);
                params.put("alpha3_code", alpha3Code);
                params.put("alpha_numeric", alphaNumeric);
                named.update("INSERT INTO tbl_iban(country, alpha2_code, alpha3_code, alpha_numeric) VALUES(:country, :alpha2_code, :alpha3_code, :alpha_numeric)", params);
            }
        }

    }

}