package com.senior.cyber.pki.root.web.pages;

import com.senior.cyber.frmk.common.base.AdminLTEResourceReference;
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
        // <!-- Font Awesome -->
        response.render(CssHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, AdminLTEResourceReference.CSS_FONT_AWESOME).getPath())));
        // <!-- Ionicons -->
        response.render(CssHeaderItem.forUrl(AdminLTEResourceReference.CSS_ION_ICONS));
        // <!-- icheck bootstrap -->
        response.render(CssHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, AdminLTEResourceReference.CSS_ICHECK_BOOTSTRAP).getPath())));
        // <!-- Theme style -->
        response.render(CssHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, AdminLTEResourceReference.CSS_THEME_STYLE).getPath())));
        // <!-- Google Font: Source Sans Pro -->
        response.render(CssHeaderItem.forUrl(AdminLTEResourceReference.CSS_GOOGLE_FONT));

        response.render(JavaScriptHeaderItem.forReference(getApplication().getJavaScriptLibrarySettings().getJQueryReference()));

        // <!-- Bootstrap 4 -->
        response.render(JavaScriptHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, AdminLTEResourceReference.JS_BOOTSTRAP_4).getPath())));
        // <!-- AdminLTE App -->
        response.render(JavaScriptHeaderItem.forReference(new FileSystemResourceReference(new File(adminLte, AdminLTEResourceReference.JS_ADMINLTE_APP).getPath())));
    }

}
