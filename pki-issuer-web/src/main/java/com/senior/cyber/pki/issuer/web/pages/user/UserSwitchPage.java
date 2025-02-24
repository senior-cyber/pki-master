package com.senior.cyber.pki.issuer.web.pages.user;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
import com.senior.cyber.pki.issuer.web.pages.MasterPage;
import com.senior.cyber.pki.issuer.web.wicket.Option;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.DropDownChoice;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.springframework.context.ApplicationContext;

import java.util.ArrayList;
import java.util.List;

@Bookmark("/user/switch")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_UserSwitch})
public class UserSwitchPage extends MasterPage {

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn user_column;
    protected UIContainer user_container;
    protected DropDownChoice<Option> user_field;
    protected List<Option> user_provider;
    protected Option user_value;

    protected Button switchButton;

    @Override
    protected void onInitData() {
        super.onInitData();
        ApplicationContext context = WicketFactory.getApplicationContext();
        UserRepository userRepository = context.getBean(UserRepository.class);
        User user = userRepository.findById(getSession().getUserId()).orElseThrow();
        this.user_provider = new ArrayList<>();
        for (User u : userRepository.findAll()) {
            if (!user.getId().equals(u.getId())) {
                this.user_provider.add(new Option(user.getId(), user.getDisplayName()));
            }
        }
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.user_column = this.row1.newUIColumn("user_column", Size.Six_6);
        this.user_container = this.user_column.newUIContainer("user_container");
        this.user_field = new DropDownChoice<>("user_field", new PropertyModel<>(this, "user_value"),
                this.user_provider);
        this.user_field.setLabel(Model.of("User"));
        this.user_field.setRequired(true);
        this.user_field.add(new ContainerFeedbackBehavior());
        this.user_container.add(this.user_field);
        this.user_container.newFeedback("user_feedback", this.user_field);

        this.row1.lastUIColumn("last_column");

        this.switchButton = new Button("switchButton") {
            @Override
            public void onSubmit() {
                switchButtonClick();
            }
        };
        this.form.add(this.switchButton);
    }

    protected void switchButtonClick() {
        getSession().switchUser(this.user_value.getIdValue());
        setResponsePage(getApplication().getHomePage());
    }

}
