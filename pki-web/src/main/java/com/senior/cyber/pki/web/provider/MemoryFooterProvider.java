package com.senior.cyber.pki.web.provider;

import com.senior.cyber.webui.frmk.model.Footer;
import com.senior.cyber.webui.frmk.provider.IFooterProvider;
import org.apache.wicket.Application;
import org.apache.wicket.markup.html.WebPage;

public class MemoryFooterProvider implements IFooterProvider {

    @Override
    public Footer fetchFooter() {
        return new Footer("PKI Master", "1.0", (Class<? extends WebPage>) Application.get().getHomePage());
    }

}
