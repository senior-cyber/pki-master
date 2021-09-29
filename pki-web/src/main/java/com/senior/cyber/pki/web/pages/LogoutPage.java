package com.senior.cyber.pki.web.pages;

import com.senior.cyber.frmk.common.base.Bookmark;
import org.apache.wicket.authroles.authentication.AuthenticatedWebSession;
import org.apache.wicket.markup.html.WebPage;

@Bookmark("/logout")
public class LogoutPage extends WebPage {

    @Override
    protected void onInitialize() {
        super.onInitialize();
        ((AuthenticatedWebSession) getSession()).signOut();
        setResponsePage(getApplication().getHomePage());
    }

}
