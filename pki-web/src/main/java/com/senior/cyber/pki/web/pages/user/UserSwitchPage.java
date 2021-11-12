package com.senior.cyber.pki.web.pages.user;

import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.web.data.SingleChoiceProvider;
import com.senior.cyber.pki.web.pages.MasterPage;
import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Option;
import com.senior.cyber.frmk.common.wicket.markup.html.form.select2.Select2SingleChoice;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.springframework.context.ApplicationContext;

@Bookmark("/user/switch")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_UserSwitch})
public class UserSwitchPage extends MasterPage {

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn user_column;
    protected UIContainer user_container;
    protected Select2SingleChoice user_field;
    protected SingleChoiceProvider<Long, String> user_provider;
    protected Option user_value;

    protected Button switchButton;

    @Override
    protected void onInitData() {
        super.onInitData();
        this.user_provider = new SingleChoiceProvider<>(
                Long.class, new LongConvertor(),
                String.class, new StringConvertor(),
                "tbl_user", "user_id", "display_name");
        this.user_provider.applyWhere("NOT", "user_id NOT IN (" + getSession().getUserId() + ")");
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
        getSession().switchUser(Long.parseLong(this.user_value.getId()));
        setResponsePage(getApplication().getHomePage());
    }

}
