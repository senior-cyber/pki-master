package com.senior.cyber.pki.web.provider;

import com.senior.cyber.webui.frmk.model.ContentHeader;
import com.senior.cyber.webui.frmk.provider.IContentHeaderProvider;

public class MemoryContentHeaderProvider implements IContentHeaderProvider {

    private final ContentHeader contentHeader;

    public MemoryContentHeaderProvider(ContentHeader contentHeader) {
        this.contentHeader = contentHeader;
    }

    @Override
    public ContentHeader fetchContentHeader() {
        return this.contentHeader;
    }

}
