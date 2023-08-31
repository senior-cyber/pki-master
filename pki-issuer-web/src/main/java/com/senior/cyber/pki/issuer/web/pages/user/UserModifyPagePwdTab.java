package com.senior.cyber.pki.issuer.web.pages.user;

import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.ContentPanel;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.tabs.Tab;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.repository.UserRepository;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.extensions.markup.html.tabs.TabbedPanel;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.validation.EqualPasswordInputValidator;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.jasypt.util.password.PasswordEncryptor;
import org.springframework.context.ApplicationContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public class UserModifyPagePwdTab extends ContentPanel {

    protected String uuid;

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn password_column;
    protected UIContainer password_container;
    protected PasswordTextField password_field;
    protected String password_value;

    protected UIRow row2;

    protected UIColumn retype_password_column;
    protected UIContainer retype_password_container;
    protected PasswordTextField retype_password_field;
    protected String retype_password_value;

    protected Button saveButton;
    protected BookmarkablePageLink<Void> cancelButton;

    public UserModifyPagePwdTab(String id, String name, TabbedPanel<Tab> containerPanel, Map<String, Object> data) {
        super(id, name, containerPanel, data);
    }

    @Override
    protected void onInitData() {
        this.uuid = getPage().getPageParameters().get("id").toString();
        loadData();
    }

    protected void loadData() {
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.password_column = this.row1.newUIColumn("password_column", Size.Four_4);
        this.password_container = this.password_column.newUIContainer("password_container");
        this.password_field = new PasswordTextField("password_field", new PropertyModel<>(this, "password_value"));
        this.password_field.setLabel(Model.of("Password"));
        this.password_field.setRequired(true);
        this.password_field.add(new ContainerFeedbackBehavior());
        this.password_container.add(this.password_field);
        this.password_container.newFeedback("password_feedback", this.password_field);

        this.row1.lastUIColumn("last_column");

        this.row2 = UIRow.newUIRow("row2", this.form);

        this.retype_password_column = this.row2.newUIColumn("retype_password_column", Size.Four_4);
        this.retype_password_container = this.retype_password_column.newUIContainer("retype_password_container");
        this.retype_password_field = new PasswordTextField("retype_password_field", new PropertyModel<>(this, "retype_password_value"));
        this.retype_password_field.setLabel(Model.of("Retype Password"));
        this.retype_password_field.setRequired(true);
        this.retype_password_field.add(new ContainerFeedbackBehavior());
        this.retype_password_container.add(this.retype_password_field);
        this.retype_password_container.newFeedback("retype_password_feedback", this.retype_password_field);

        this.row2.lastUIColumn("last_column");

        this.saveButton = new Button("saveButton") {
            @Override
            public void onSubmit() {
                saveButtonClick();
            }
        };
        this.form.add(this.saveButton);

        this.form.add(new EqualPasswordInputValidator(this.password_field, this.retype_password_field));

        this.cancelButton = new BookmarkablePageLink<>("cancelButton", UserBrowsePage.class);
        this.form.add(this.cancelButton);
    }

    protected void saveButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        Optional<User> userOptional = userRepository.findById(this.uuid);

        User user = userOptional.orElseThrow();

        PasswordEncryptor passwordEncryptor = context.getBean(PasswordEncryptor.class);
        passwordEncryptor.encryptPassword(this.password_value);
        userRepository.save(user);

        setResponsePage(UserBrowsePage.class);
    }

}
