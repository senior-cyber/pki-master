package com.senior.cyber.pki.web.gson;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import org.apache.commons.lang3.time.DateFormatUtils;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

public class Iso8601Date extends TypeAdapter<Date> {

    @Override
    public void write(JsonWriter out, Date value) throws IOException {
        if (value == null) {
            out.nullValue();
        } else {
            out.value(DateFormatUtils.ISO_8601_EXTENDED_DATE_FORMAT.format(value));
        }
    }

    @Override
    public Date read(JsonReader in) throws IOException {
        try {
            return DateFormatUtils.ISO_8601_EXTENDED_DATE_FORMAT.parse(in.nextString());
        } catch (ParseException e) {
            throw new IOException(e);
        }
    }

}