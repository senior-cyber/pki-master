package com.senior.cyber.pki.web.provider;

import com.senior.cyber.frmk.common.model.ContentHeader;
import com.senior.cyber.frmk.common.provider.IContentHeaderProvider;

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
