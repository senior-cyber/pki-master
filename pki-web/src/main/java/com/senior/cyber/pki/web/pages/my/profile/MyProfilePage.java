package com.senior.cyber.pki.web.pages.my.profile;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.TabbedPanel;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.web.pages.MasterPage;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;

import java.util.ArrayList;
import java.util.List;

@Bookmark("/my/profile")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyProfile})
public class MyProfilePage extends MasterPage {

    protected TabbedPanel tabs;

    protected Tab info_tab;

    protected Tab pwd_tab;

    protected Tab address_tab;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.info_tab = new Tab("info", "My Info", MyProfilePageInfoTab.class);
        if (getSession().getQueue().isEmpty()) {
            this.pwd_tab = new Tab("pwd", "Password", MyProfilePagePwdTab.class);
        }
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        List<Tab> tabs = new ArrayList<>();
        if (this.info_tab != null) {
            tabs.add(this.info_tab);
        }
        if (this.pwd_tab != null) {
            tabs.add(this.pwd_tab);
        }
        if (this.address_tab != null) {
            tabs.add(this.address_tab);
        }
        this.tabs = new TabbedPanel("tabs", tabs);
        body.add(this.tabs);
    }

}
