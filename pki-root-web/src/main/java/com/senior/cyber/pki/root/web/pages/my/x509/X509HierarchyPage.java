package com.senior.cyber.pki.root.web.pages.my.x509;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.tree.NestedTree;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.TabbedPanel;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.root.web.pages.MasterPage;
import com.senior.cyber.pki.root.web.pages.my.issuer.IssuerBrowsePage;
import com.senior.cyber.pki.root.web.pages.my.issuer.IssuerGeneratePage;
import com.senior.cyber.pki.root.web.pages.my.root.RootGeneratePage;
import com.senior.cyber.pki.root.web.pages.my.root.RootGeneratePageInfoTab;
import com.senior.cyber.pki.root.web.provider.CertificateHierarchyProvider;
import org.apache.wicket.Component;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.IModel;
import org.apache.wicket.request.mapper.parameter.PageParameters;

import java.util.ArrayList;
import java.util.List;

@Bookmark("/my/x509/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyRootBrowse})
public class X509HierarchyPage extends MasterPage {

    protected BookmarkablePageLink<Void> createButton;

    protected NestedTree<Certificate> x509_tree;
    protected CertificateHierarchyProvider x509_provider;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.x509_provider = new CertificateHierarchyProvider();
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.createButton = new BookmarkablePageLink<>("createButton", RootGeneratePage.class);
        body.add(this.createButton);

        this.x509_tree = new NestedTree<>("x509_tree", this.x509_provider, this::dataNewLabel, this::dataNewLink);
        body.add(this.x509_tree);
    }

    protected MarkupContainer dataNewLink(String s, IModel<Certificate> model) {
        long id = model.getObject().getSerial();
        PageParameters parameters = new PageParameters();
        parameters.add("serial", id);
        BookmarkablePageLink<Void> link = new BookmarkablePageLink<>(s, IssuerGeneratePage.class, parameters);
        return link;
    }

    protected Component dataNewLabel(String s, IModel<Certificate> model) {
        return new Label(s, model.getObject().getCommonName());
    }

}
