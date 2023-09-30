package com.senior.cyber.pki.issuer.web.pages.user;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.jakarta.persistence.Sql;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Option;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Select2SingleChoice;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.User_;
import com.senior.cyber.pki.issuer.web.data.Select2ChoiceProvider;
import com.senior.cyber.pki.issuer.web.pages.MasterPage;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;

@Bookmark("/user/switch")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_UserSwitch})
public class UserSwitchPage extends MasterPage {

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn user_column;
    protected UIContainer user_container;
    protected Select2SingleChoice user_field;
    protected Select2ChoiceProvider user_provider;
    protected Option user_value;

    protected Button switchButton;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.user_provider = new Select2ChoiceProvider(Sql.table(User_.class), Sql.column(User_.id), Sql.column(User_.displayName));
        this.user_provider.applyWhere("NOT", Sql.column(User_.id) + " NOT IN (" + getSession().getUserId() + ")");
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.form = new Form<>("form");
        body.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.user_column = this.row1.newUIColumn("user_column", Size.Six_6);
        this.user_container = this.user_column.newUIContainer("user_container");
        this.user_field = new Select2SingleChoice("user_field", new PropertyModel<>(this, "user_value"),
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
        getSession().switchUser(this.user_value.getId());
        setResponsePage(getApplication().getHomePage());
    }

}
