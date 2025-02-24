package com.senior.cyber.pki.root.web.pages;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.LTEAdminProperties;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ComponentFeedbackPanel;
import com.senior.cyber.pki.root.web.factory.WebSession;
import org.apache.wicket.markup.head.CssHeaderItem;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.resource.FileSystemResourceReference;

import java.io.File;
import java.util.UUID;

@Bookmark("/login")
public class LoginPage extends WebPage {

    protected Form<Void> form = null;

    protected TextField<String> username_field;
    protected ComponentFeedbackPanel username_feedback;
    protected String username_value;

    protected PasswordTextField password_field;
    protected ComponentFeedbackPanel password_feedback;
    protected String password_value;

    protected Button loginButton;

    @Override
    protected void onInitialize() {
        super.onInitialize();
        this.form = new Form<>("form");
        add(this.form);

        this.username_field = new TextField<>("username_field", new PropertyModel<>(this, "username_value"));
        this.username_field.setLabel(Model.of("Username"));
        this.username_field.setRequired(true);
        this.form.add(this.username_field);
        this.username_feedback = new ComponentFeedbackPanel("username_feedback", this.username_field);
        this.form.add(this.username_feedback);

        this.password_field = new PasswordTextField("password_field", new PropertyModel<>(this, "password_value"));
        this.password_field.setLabel(Model.of("Password"));
        this.password_field.setRequired(true);
        this.form.add(this.password_field);
        this.password_feedback = new ComponentFeedbackPanel("password_feedback", this.password_field);
        this.form.add(this.password_feedback);

        this.loginButton = new Button("loginButton") {
            @Override
            public void onSubmit() {
                loginButtonClick();
            }
        };
        this.form.add(this.loginButton);

        add(new BookmarkablePageLink<>("registerPage", RegisterPage.class));
        add(new BookmarkablePageLink<>("forgetPasswordPage", ForgetPasswordPage.class));
    }

    protected void loginButtonClick() {
        WebSession webSession = (WebSession) getSession();
        boolean valid = webSession.signIn(this.username_value, this.password_value);
        if (!valid) {
            this.username_field.error("invalid");
            this.password_field.error("invalid");
        } else {
            setResponsePage(getApplication().getHomePage());
        }
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        File adminLte = ((LTEAdminProperties) WebApplication.get()).getWebUiProperties().getAdminLte();
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/@fontsource/source-sans-3@5.0.12/index.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/overlayscrollbars@2.10.1/styles/overlayscrollbars.min.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"));
        response.render(CssHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, "/css/adminlte.css").getPath())));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/apexcharts@3.37.1/dist/apexcharts.css"));
        response.render(CssHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/overlayscrollbars@2.10.1/browser/overlayscrollbars.browser.es6.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"));
        response.render(JavaScriptHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, "/js/adminlte.js").getPath())));
        StringBuilder js = new StringBuilder();
        js.append("<script>").append("\n");
        js.append("    const SELECTOR_SIDEBAR_WRAPPER = \".sidebar-wrapper\";").append("\n");
        js.append("    const Default = {").append("\n");
        js.append("        scrollbarTheme: \"os-theme-light\",").append("\n");
        js.append("        scrollbarAutoHide: \"leave\",").append("\n");
        js.append("        scrollbarClickScroll: true,").append("\n");
        js.append("    };").append("\n");
        js.append("    document.addEventListener(\"DOMContentLoaded\", function () {").append("\n");
        js.append("        const sidebarWrapper = document.querySelector(SELECTOR_SIDEBAR_WRAPPER);").append("\n");
        js.append("        if (").append("\n");
        js.append("            sidebarWrapper &&").append("\n");
        js.append("            typeof OverlayScrollbarsGlobal?.OverlayScrollbars !== \"undefined\"").append("\n");
        js.append("        ) {").append("\n");
        js.append("            OverlayScrollbarsGlobal.OverlayScrollbars(sidebarWrapper, {").append("\n");
        js.append("                scrollbars: {").append("\n");
        js.append("                    theme: Default.scrollbarTheme,").append("\n");
        js.append("                    autoHide: Default.scrollbarAutoHide,").append("\n");
        js.append("                    clickScroll: Default.scrollbarClickScroll,").append("\n");
        js.append("                },").append("\n");
        js.append("            });").append("\n");
        js.append("        }").append("\n");
        js.append("    });").append("\n");
        js.append("</script>").append("\n");
        response.render(JavaScriptHeaderItem.forScript(js.toString(), UUID.randomUUID().toString()));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/apexcharts@3.37.1/dist/apexcharts.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/js/jsvectormap.min.js"));
        response.render(JavaScriptHeaderItem.forUrl("https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/maps/world.js"));
    }

}
