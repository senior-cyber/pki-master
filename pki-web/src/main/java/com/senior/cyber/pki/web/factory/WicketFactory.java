package com.senior.cyber.pki.web.factory;

import com.senior.cyber.pki.web.pages.ErrorPage;
import com.senior.cyber.pki.web.pages.LoginPage;
import com.senior.cyber.pki.web.pages.my.certificate.CertificateBrowsePage;
import org.apache.wicket.Page;
import org.apache.wicket.authroles.authentication.AbstractAuthenticatedWebSession;
import org.apache.wicket.markup.html.WebPage;

public class WicketFactory extends com.senior.cyber.frmk.common.base.AuthenticatedWicketFactory {

    @Override
    protected void init() {
        super.init();
        getApplicationSettings().setInternalErrorPage(ErrorPage.class);
        getApplicationSettings().setAccessDeniedPage(ErrorPage.class);
        getApplicationSettings().setPageExpiredErrorPage(ErrorPage.class);
    }

    @Override
    protected Class<? extends AbstractAuthenticatedWebSession> getWebSessionClass() {
        return WebSession.class;
    }

    @Override
    protected Class<? extends WebPage> getSignInPageClass() {
        return LoginPage.class;
    }

    @Override
    public Class<? extends Page> getHomePage() {
        return CertificateBrowsePage.class;
    }

}
