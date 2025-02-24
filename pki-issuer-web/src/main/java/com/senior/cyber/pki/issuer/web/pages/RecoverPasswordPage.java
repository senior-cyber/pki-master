package com.senior.cyber.pki.issuer.web.pages;

import com.senior.cyber.frmk.common.base.AdminLTEResourceReference;
import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.LTEAdminProperties;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ComponentFeedbackPanel;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.markup.head.CssHeaderItem;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.validation.EqualPasswordInputValidator;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.resource.FileSystemResourceReference;
import org.apache.wicket.validation.ValidationError;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.util.password.PasswordEncryptor;
import org.springframework.context.ApplicationContext;

import java.io.File;
import java.util.Optional;

@Bookmark("/recover/password")
public class RecoverPasswordPage extends WebPage {

    protected String uuid;

    protected Form<Void> form = null;

    protected PasswordTextField receive_password_field;
    protected ComponentFeedbackPanel receive_password_feedback;
    protected String receive_password_value;

    protected PasswordTextField new_password_field;
    protected ComponentFeedbackPanel new_password_feedback;
    protected String new_password_value;

    protected PasswordTextField retype_new_password_field;
    protected ComponentFeedbackPanel retype_new_password_feedback;
    protected String retype_new_password_value;

    protected Button okayButton;

    public RecoverPasswordPage(String userId) {
        this.uuid = userId;
    }

    @Override
    protected void onInitialize() {
        super.onInitialize();
        this.form = new Form<>("form");
        add(this.form);

        this.receive_password_field = new PasswordTextField("receive_password_field", new PropertyModel<>(this, "receive_password_value"));
        this.receive_password_field.setLabel(Model.of("Receive Password"));
        this.receive_password_field.setRequired(true);
        this.form.add(this.receive_password_field);
        this.receive_password_feedback = new ComponentFeedbackPanel("receive_password_feedback", this.receive_password_field);
        this.form.add(this.receive_password_feedback);

        this.new_password_field = new PasswordTextField("new_password_field", new PropertyModel<>(this, "new_password_value"));
        this.new_password_field.setLabel(Model.of("New Password"));
        this.new_password_field.setRequired(true);
        this.form.add(this.new_password_field);
        this.new_password_feedback = new ComponentFeedbackPanel("new_password_feedback", this.new_password_field);
        this.form.add(this.new_password_feedback);

        this.retype_new_password_field = new PasswordTextField("retype_new_password_field", new PropertyModel<>(this, "retype_new_password_value"));
        this.retype_new_password_field.setLabel(Model.of("Retype New Password"));
        this.retype_new_password_field.setRequired(true);
        this.form.add(this.retype_new_password_field);
        this.retype_new_password_feedback = new ComponentFeedbackPanel("retype_new_password_feedback", this.retype_new_password_field);
        this.form.add(this.retype_new_password_feedback);

        this.form.add(new EqualPasswordInputValidator(this.new_password_field, this.retype_new_password_field));

        this.okayButton = new Button("okayButton") {
            @Override
            public void onSubmit() {
                okayButtonClick();
            }
        };
        this.form.add(this.okayButton);

        add(new BookmarkablePageLink<>("loginPage", LoginPage.class));
    }

    protected void okayButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        PasswordEncryptor passwordEncryptor = context.getBean(PasswordEncryptor.class);
        Optional<User> optionalUser = userRepository.findById(this.uuid);
        User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
        try {
            if (passwordEncryptor.checkPassword(this.receive_password_value, user.getPassword())) {
                user.setPassword(passwordEncryptor.encryptPassword(this.new_password_value));
                userRepository.save(user);
                setResponsePage(LoginPage.class);
            }
        } catch (EncryptionOperationNotPossibleException | EncryptionInitializationException e) {
            this.receive_password_field.error(new ValidationError("invalid"));
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
