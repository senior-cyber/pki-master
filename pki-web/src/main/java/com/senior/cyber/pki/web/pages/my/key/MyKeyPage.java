package com.senior.cyber.pki.web.pages.my.key;

import com.google.crypto.tink.*;
import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.cell.TextCell;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.translator.IHtmlTranslator;
import com.senior.cyber.frmk.common.wicket.layout.Size;
import com.senior.cyber.frmk.common.wicket.layout.UIColumn;
import com.senior.cyber.frmk.common.wicket.layout.UIContainer;
import com.senior.cyber.frmk.common.wicket.layout.UIRow;
import com.senior.cyber.frmk.common.wicket.markup.html.panel.ContainerFeedbackBehavior;
import com.senior.cyber.pki.dao.entity.Key;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.web.configuration.Mode;
import com.senior.cyber.pki.web.data.MySqlDataProvider;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.pages.MasterPage;
import com.senior.cyber.pki.web.repository.KeyRepository;
import com.senior.cyber.pki.web.repository.UserRepository;
import com.senior.cyber.pki.web.utility.Crypto;
import com.senior.cyber.pki.web.validator.KeyNameValidator;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.extensions.markup.html.repeater.data.table.IColumn;
import org.apache.wicket.extensions.markup.html.repeater.data.table.filter.FilterForm;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.PropertyModel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.util.text.AES256TextEncryptor;
import org.springframework.context.ApplicationContext;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.persistence.Tuple;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.*;

@Bookmark("/my/kek")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyKey})
public class MyKeyPage extends MasterPage implements IHtmlTranslator<Tuple> {

    protected Form<Void> form;

    protected UIRow row1;

    protected UIColumn name_column;
    protected UIContainer name_container;
    protected TextField<String> name_field;
    protected String name_value;

    protected Button createButton;

    protected FilterForm<Map<String, Expression<?>>> key_browse_form;
    protected MySqlDataProvider key_browse_provider;
    protected List<IColumn<Tuple, String>> key_browse_column;
    protected AbstractDataTable<Tuple, String> key_browse_table;

    protected List<Long> shown = new ArrayList<>();

    protected transient AES256TextEncryptor textEncryptor;

    @Override
    protected void onInitData() {
        super.onInitData();
        WebSession session = getSession();
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        this.key_browse_provider = new MySqlDataProvider("tbl_key");
        this.key_browse_provider.setSort("key_id", SortOrder.DESCENDING);
        if (applicationConfiguration.getMode() == Mode.Individual) {
            this.key_browse_provider.applyWhere("user", "user_id = " + session.getUserId());
        }
        this.key_browse_provider.setCountField("key_id");
        this.key_browse_provider.selectNormalColumn("user_id", "user_id", new LongConvertor());

        this.key_browse_column = new ArrayList<>();
        this.key_browse_column.add(Column.normalColumn(Model.of("ID"), "uuid", "key_id", this.key_browse_provider, new LongConvertor()));
        this.key_browse_column.add(Column.normalColumn(Model.of("Client ID"), "client_id", "client_id", this.key_browse_provider, new StringConvertor()));
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_ShowSecret_Action)) {
                this.key_browse_column.add(Column.normalColumn(Model.of("Client Secret"), "client_secret", "client_secret", this.key_browse_provider, new StringConvertor(), this));
            }
        }
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_Delete_Action) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_ShowSecret_Action)) {
                this.key_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::key_browse_action_link, this::key_browse_action_click));
            }
        }
    }

    @Override
    public ItemPanel htmlColumn(String key, IModel<String> display, Tuple object) {
        long userId = object.get("user_id", long.class);
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_ShowSecret_Action)) {
            } else {
                return new TextCell("");
            }
        }
        if (textEncryptor == null) {
            textEncryptor = new AES256TextEncryptor();
            try {
                textEncryptor.setPassword(getSession().getPwd());
            } catch (EncryptionOperationNotPossibleException e) {
            }
        }
        long uuid = object.get("uuid", long.class);
        if (shown.contains(uuid)) {
            try {
                String client_secret = object.get("client_secret", String.class);
                return new TextCell(textEncryptor.decrypt(client_secret));
            } catch (EncryptionOperationNotPossibleException e) {
                return new TextCell("");
            }
        } else {
            if (userId == getSession().getQueue().get(0)) {
                return new TextCell("*********");
            } else {
                return new TextCell("");
            }
        }
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        WebMarkupContainer createBlock = new WebMarkupContainer("createBlock");
        body.add(createBlock);
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_Create_Action)) {
                createBlock.setVisible(true);
            } else {
                createBlock.setVisible(false);
            }
        }

        this.form = new Form<>("form");
        createBlock.add(this.form);

        this.row1 = UIRow.newUIRow("row1", this.form);

        this.name_column = this.row1.newUIColumn("name_column", Size.Six_6);
        this.name_container = this.name_column.newUIContainer("name_container");
        this.name_field = new TextField<>("name_field", new PropertyModel<>(this, "name_value"));
        this.name_field.setRequired(true);
        this.name_field.setLabel(Model.of("Name"));
        this.name_field.add(new KeyNameValidator());
        this.name_field.add(new ContainerFeedbackBehavior());
        this.name_container.add(this.name_field);
        this.name_container.newFeedback("name_feedback", this.name_field);

        this.row1.lastUIColumn("last_column");

        this.createButton = new Button("createButton") {
            @Override
            public void onSubmit() {
                createButtonClick();
            }
        };
        this.form.add(this.createButton);

        this.key_browse_form = new FilterForm<>("key_browse_form", this.key_browse_provider);
        body.add(this.key_browse_form);

        this.key_browse_table = new DataTable<>("key_browse_table", this.key_browse_column, this.key_browse_provider, 20);
        this.key_browse_form.add(this.key_browse_table);
    }

    protected void createButtonClick() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_Create_Action)) {
            } else {
                throw new WicketRuntimeException("No Permission");
            }
        }
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
            generator.init(256);

            SecretKey secretKey = generator.generateKey();

            Crypto crypto = context.getBean(Crypto.class);
            UserRepository userRepository = context.getBean(UserRepository.class);
            Optional<User> optionalUser = userRepository.findById(getSession().getUserId());
            User user = optionalUser.orElseThrow(() -> new WicketRuntimeException(""));
            KeyRepository keyRepository = context.getBean(KeyRepository.class);
            String clientSecret = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            AES256TextEncryptor textEncryptor = new AES256TextEncryptor();
            textEncryptor.setPassword(getSession().getPwd());

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            KeysetWriter writer = JsonKeysetWriter.withOutputStream(stream);

            KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"));

            CleartextKeysetHandle.write(handle, writer);

            String json = stream.toString(StandardCharsets.UTF_8);

            Key maserKey = new Key();
            maserKey.setClientId(this.name_value);
            maserKey.setKek(crypto.encrypt(secretKey, json));
            maserKey.setUser(user);
            maserKey.setClientSecret(textEncryptor.encrypt(clientSecret));
            keyRepository.save(maserKey);
        } catch (GeneralSecurityException | IOException e) {
            throw new WicketRuntimeException(e);
        }
    }

    protected List<ActionItem> key_browse_action_link(String link, Tuple model) {
        long uuid = model.get("uuid", long.class);
        long userId = model.get("user_id", long.class);
        List<ActionItem> actions = new ArrayList<>(0);
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_Delete_Action)) {
                actions.add(new ActionItem("Delete", Model.of("Delete"), ItemCss.DANGER));
            }
        }
        if (shown.contains(uuid)) {
            actions.add(new ActionItem("Hide Secret", Model.of("Hide Secret"), ItemCss.SUCCESS));
        } else {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_ShowSecret_Action)) {
                    if (getSession().getQueue().get(0) == userId) {
                        actions.add(new ActionItem("Show Secret", Model.of("Show Secret"), ItemCss.WARNING));
                    }
                }
            }
        }
        return actions;
    }

    protected void key_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        KeyRepository keyRepository = context.getBean(KeyRepository.class);
        long uuid = model.get("uuid", long.class);
        if ("Delete".equals(link)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_Delete_Action)) {
                } else {
                    throw new WicketRuntimeException("No Permission");
                }
            }
            keyRepository.deleteById(uuid);
            target.add(this.key_browse_table);
        } else if ("Show Secret".equals(link)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyKey_ShowSecret_Action)) {
                } else {
                    throw new WicketRuntimeException("No Permission");
                }
            }
            shown.add(uuid);
            target.add(this.key_browse_table);
        } else if ("Hide Secret".equals(link)) {
            shown.remove(uuid);
            target.add(this.key_browse_table);
        }
    }

}
