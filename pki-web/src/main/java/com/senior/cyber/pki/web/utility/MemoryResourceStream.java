package com.senior.cyber.pki.web.utility;

import org.apache.wicket.util.lang.Bytes;
import org.apache.wicket.util.resource.IResourceStream;
import org.apache.wicket.util.resource.ResourceStreamNotFoundException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Locale;

public class MemoryResourceStream implements IResourceStream {

    private final String contentType;

    private final byte[] data;

    public MemoryResourceStream(String contentType, byte[] data) {
        this.contentType = contentType;
        this.data = data;
    }

    @Override
    public String getContentType() {
        return this.contentType;
    }

    @Override
    public Bytes length() {
        return null;
    }

    @Override
    public InputStream getInputStream() throws ResourceStreamNotFoundException {
        return new ByteArrayInputStream(this.data);
    }

    @Override
    public void close() throws IOException {
    }

    @Override
    public Locale getLocale() {
        return null;
    }

    @Override
    public void setLocale(Locale locale) {
    }

    @Override
    public String getStyle() {
        return null;
    }

    @Override
    public void setStyle(String style) {
    }

    @Override
    public String getVariation() {
        return null;
    }

    @Override
    public void setVariation(String variation) {
    }

    @Override
    public Instant lastModifiedTime() {
        return Instant.now();
    }

}
