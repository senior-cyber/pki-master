package com.senior.cyber.pki.web.pages.user;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.TabbedPanel;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.web.pages.MasterPage;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;

import java.util.ArrayList;
import java.util.List;

@Bookmark("/user/modify")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_UserModify})
public class UserModifyPage extends MasterPage {

    protected TabbedPanel tabs;

    protected Tab info_tab;

    protected Tab pwd_tab;

    protected Tab group_tab;

    protected Tab granted_role_tab;

    protected Tab denied_role_tab;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.info_tab = new Tab("info", "Information", UserModifyPageInfoTab.class);
//        this.pwd_tab = new Tab("pwd", "Password", UserModifyPagePwdTab.class);
        this.group_tab = new Tab("group", "Group Permission", UserModifyPageGroupTab.class);
        this.granted_role_tab = new Tab("granted_role", "Granted Individual Permission", UserModifyPageGrantedRoleTab.class);
        this.denied_role_tab = new Tab("denied_role", "Denied Individual Permission", UserModifyPageDeniedRoleTab.class);
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
        if (this.group_tab != null) {
            tabs.add(this.group_tab);
        }
        if (this.granted_role_tab != null) {
            tabs.add(this.granted_role_tab);
        }
        if (this.denied_role_tab != null) {
            tabs.add(this.denied_role_tab);
        }
        this.tabs = new TabbedPanel("tabs", tabs);
        body.add(this.tabs);
    }

}
