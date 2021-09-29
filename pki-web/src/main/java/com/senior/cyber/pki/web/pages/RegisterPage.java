package com.senior.cyber.pki.web.pages;

import com.senior.cyber.pki.dao.entity.Group;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.repository.GroupRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.pki.web.validator.UserEmailAddressValidator;
import com.senior.cyber.pki.web.validator.UserLoginValidator;
import com.senior.cyber.frmk.common.base.AdminLTEResourceReference;
import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ComponentFeedbackPanel;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.markup.head.CssHeaderItem;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.form.validation.EqualPasswordInputValidator;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.validation.validator.EmailAddressValidator;
import org.jasypt.util.password.PasswordEncryptor;
import org.springframework.context.ApplicationContext;

import java.util.*;

@Bookmark("/register")
public class RegisterPage extends WebPage {

    protected Form<Void> form = null;

    protected TextField<String> display_name_field;
    protected ComponentFeedbackPanel display_name_feedback;
    protected String display_name_value;

    protected TextField<String> email_address_field;
    protected ComponentFeedbackPanel email_address_feedback;
    protected String email_address_value;

    protected TextField<String> username_field;
    protected ComponentFeedbackPanel username_feedback;
    protected String username_value;

    protected PasswordTextField password_field;
    protected ComponentFeedbackPanel password_feedback;
    protected String password_value;

    protected PasswordTextField retype_password_field;
    protected ComponentFeedbackPanel retype_password_feedback;
    protected String retype_password_value;

    protected Button registerButton;

    @Override
    protected void onInitialize() {
        super.onInitialize();
        this.form = new Form<>("form");
        add(this.form);

        this.display_name_field = new TextField<>("display_name_field", new PropertyModel<>(this, "display_name_value"));
        this.display_name_field.setLabel(Model.of("Display Name"));
        this.display_name_field.setRequired(true);
        this.form.add(this.display_name_field);
        this.display_name_feedback = new ComponentFeedbackPanel("display_name_feedback", this.display_name_field);
        this.form.add(this.display_name_feedback);

        this.email_address_field = new TextField<>("email_address_field", new PropertyModel<>(this, "email_address_value"));
        this.email_address_field.setLabel(Model.of("Email Address"));
        this.email_address_field.setRequired(true);
        this.email_address_field.add(new UserEmailAddressValidator());
        this.email_address_field.add(EmailAddressValidator.getInstance());
        this.form.add(this.email_address_field);
        this.email_address_feedback = new ComponentFeedbackPanel("email_address_feedback", this.email_address_field);
        this.form.add(this.email_address_feedback);

        this.username_field = new TextField<>("username_field", new PropertyModel<>(this, "username_value"));
        this.username_field.setLabel(Model.of("Username"));
        this.username_field.setRequired(true);
        this.username_field.add(new UserLoginValidator());
        this.form.add(this.username_field);
        this.username_feedback = new ComponentFeedbackPanel("username_feedback", this.username_field);
        this.form.add(this.username_feedback);

        this.password_field = new PasswordTextField("password_field", new PropertyModel<>(this, "password_value"));
        this.password_field.setLabel(Model.of("Password"));
        this.password_field.setRequired(true);
        this.form.add(this.password_field);
        this.password_feedback = new ComponentFeedbackPanel("password_feedback", this.password_field);
        this.form.add(this.password_feedback);

        this.retype_password_field = new PasswordTextField("retype_password_field", new PropertyModel<>(this, "retype_password_value"));
        this.retype_password_field.setLabel(Model.of("Retype Password"));
        this.retype_password_field.setRequired(true);
        this.form.add(this.retype_password_field);
        this.retype_password_feedback = new ComponentFeedbackPanel("retype_password_feedback", this.retype_password_field);
        this.form.add(this.retype_password_feedback);

        this.form.add(new EqualPasswordInputValidator(this.password_field, this.retype_password_field));

        this.registerButton = new Button("registerButton") {
            @Override
            public void onSubmit() {
                registerButtonClick();
            }
        };
        this.form.add(this.registerButton);

        add(new BookmarkablePageLink<>("loginPage", LoginPage.class));
    }

    protected void registerButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        GroupRepository groupRepository = context.getBean(GroupRepository.class);
        PasswordEncryptor passwordEncryptor = context.getBean(PasswordEncryptor.class);

        Optional<Group> optionalGroup = groupRepository.findByName("Registered");
        Group group = optionalGroup.orElseThrow(() -> new WicketRuntimeException(""));

        User user = new User();
        user.setDisplayName(this.display_name_value);
        user.setEnabled(true);
        user.setEmailAddress(this.email_address_value);
        user.setLogin(this.username_value);
        user.setLastSeen(new Date());
        user.setPassword(passwordEncryptor.encryptPassword(this.password_value));
        Map<String, Group> groups = new HashMap<>();
        groups.put(UUID.randomUUID().toString(), group);
        user.setGroups(groups);
        userRepository.save(user);

        setResponsePage(LoginPage.class);
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        // <!-- Font Awesome -->
        response.render(CssHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.CSS_FONT_AWESOME)));
        // <!-- Ionicons -->
        response.render(CssHeaderItem.forUrl(AdminLTEResourceReference.CSS_ION_ICONS));
        // <!-- icheck bootstrap -->
        response.render(CssHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.CSS_ICHECK_BOOTSTRAP)));
        // <!-- Theme style -->
        response.render(CssHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.CSS_THEME_STYLE)));
        // <!-- Google Font: Source Sans Pro -->
        response.render(CssHeaderItem.forUrl(AdminLTEResourceReference.CSS_GOOGLE_FONT));

        response.render(JavaScriptHeaderItem.forReference(getApplication().getJavaScriptLibrarySettings().getJQueryReference()));

        // <!-- Bootstrap 4 -->
        response.render(JavaScriptHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.JS_BOOTSTRAP_4)));
        // <!-- AdminLTE App -->
        response.render(JavaScriptHeaderItem.forReference(new AdminLTEResourceReference(AdminLTEResourceReference.JS_ADMINLTE_APP)));
    }

}
