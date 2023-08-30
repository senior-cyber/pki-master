package com.senior.cyber.pki.root.web.pages.user;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.root.web.factory.WebSession;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.markup.html.WebPage;

@Bookmark("/user/exit")
@AuthorizeInstantiation({Role.NAME_Page_UserExit})
public class UserExitPage extends WebPage {

    @Override
    protected void onInitialize() {
        super.onInitialize();
        WebSession session = (WebSession) getSession();
        session.exitCurrent();
        setResponsePage(getApplication().getHomePage());
    }

}
