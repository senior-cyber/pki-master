package com.senior.cyber.pki.web.pages;

import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.provider.MemoryFooterProvider;
import com.senior.cyber.pki.web.provider.MemoryMainSidebarProvider;
import com.senior.cyber.pki.web.provider.MemoryThemeProvider;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.model.IModel;
import org.apache.wicket.request.mapper.parameter.PageParameters;

public abstract class MasterPage extends com.senior.cyber.frmk.common.wicket.layout.MasterPage {

    public MasterPage() {
    }

    public MasterPage(IModel<?> model) {
        super(model);
    }

    public MasterPage(PageParameters parameters) {
        super(parameters);
    }

    @Override
    protected void onInitData() {
        this.mainSidebarProvider = new MemoryMainSidebarProvider(getSession());
        this.footerProvider = new MemoryFooterProvider();
        this.themeProvider = new MemoryThemeProvider();
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
    }

    @Override
    public WebSession getSession() {
        return (WebSession) super.getSession();
    }

}
