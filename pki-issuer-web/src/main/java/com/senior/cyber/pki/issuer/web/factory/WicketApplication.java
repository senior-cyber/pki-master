package com.senior.cyber.pki.issuer.web.factory;

import com.senior.cyber.frmk.common.base.AbstractAuthenticatedWebApplication;
import com.senior.cyber.frmk.common.base.WebUiProperties;
import com.senior.cyber.frmk.common.exception.UnauthorizedInstantiationException;
import com.senior.cyber.pki.issuer.web.pages.DeniedPage;
import com.senior.cyber.pki.issuer.web.pages.ErrorPage;
import com.senior.cyber.pki.issuer.web.pages.LoginPage;
import com.senior.cyber.pki.issuer.web.pages.my.profile.MyProfilePage;
import org.apache.wicket.Component;
import org.apache.wicket.Page;
import org.apache.wicket.authroles.authentication.AbstractAuthenticatedWebSession;
import org.apache.wicket.markup.html.WebPage;

public class WicketApplication extends AbstractAuthenticatedWebApplication {

    public WicketApplication(WebUiProperties webUiProperties) {
        super(webUiProperties);
    }

    @Override
    protected void init() {
        super.init();
        getApplicationSettings().setInternalErrorPage(ErrorPage.class);
        getApplicationSettings().setAccessDeniedPage(DeniedPage.class);
        getApplicationSettings().setPageExpiredErrorPage(ErrorPage.class);
        setExceptionMapperProvider(ExceptionMapper::new);
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
        return MyProfilePage.class;
    }

    @Override
    protected void onUnauthorizedPage(Component page) {
        throw new UnauthorizedInstantiationException(page.getClass());
    }

}
