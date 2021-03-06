package com.senior.cyber.pki.web.pages.my.root;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.Permission;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.cell.ClickableCell;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.DateConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.translator.IHtmlTranslator;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.web.configuration.Mode;
import com.senior.cyber.pki.web.data.MySqlDataProvider;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.pages.MasterPage;
import com.senior.cyber.pki.web.repository.RootRepository;
import com.senior.cyber.pki.web.utility.MemoryResourceStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.extensions.markup.html.repeater.data.table.IColumn;
import org.apache.wicket.extensions.markup.html.repeater.data.table.filter.FilterForm;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.markup.html.link.Link;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.request.IRequestCycle;
import org.apache.wicket.request.handler.resource.ResourceStreamRequestHandler;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.request.resource.ContentDisposition;
import org.apache.wicket.util.resource.IResourceStream;
import org.springframework.context.ApplicationContext;

import javax.persistence.Tuple;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

@Bookmark("/my/root/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyRootBrowse})
public class RootBrowsePage extends MasterPage implements IHtmlTranslator<Tuple> {

    protected FilterForm<Map<String, Expression<?>>> root_browse_form;
    protected MySqlDataProvider root_browse_provider;
    protected List<IColumn<Tuple, String>> root_browse_column;
    protected AbstractDataTable<Tuple, String> root_browse_table;

    protected BookmarkablePageLink<Void> createButton;

    @Override
    protected void onInitData() {
        super.onInitData();
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        WebSession session = getSession();
        this.root_browse_provider = new MySqlDataProvider("tbl_root");
        this.root_browse_provider.setSort("root_id", SortOrder.DESCENDING);
        if (applicationConfiguration.getMode() == Mode.Individual) {
            this.root_browse_provider.applyWhere("user", "user_id = " + session.getUserId());
        }
        this.root_browse_provider.setCountField("root_id");

        this.root_browse_column = new ArrayList<>();
        this.root_browse_column.add(Column.normalColumn(Model.of("ID"), "uuid", "root_id", this.root_browse_provider, new LongConvertor()));
        this.root_browse_column.add(Column.normalColumn(Model.of("Name"), "common_name", "common_name", this.root_browse_provider, new StringConvertor()));
        this.root_browse_column.add(Column.normalColumn(Model.of("Valid Until"), "valid_until", "valid_until", this.root_browse_provider, new DateConvertor()));
        this.root_browse_column.add(Column.normalColumn(Model.of("Status"), "status", "status", this.root_browse_provider, new StringConvertor()));
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyRootBrowse_Download_Action)) {
                this.root_browse_column.add(Column.normalColumn(Model.of("Download"), "download", "status", this.root_browse_provider, new StringConvertor(), this));
            }
        } else {
            this.root_browse_column.add(Column.normalColumn(Model.of("Download"), "download", "status", this.root_browse_provider, new StringConvertor(), this));
        }
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyRootBrowse_Revoke_Action) || getSession().getRoles().hasRole(Role.NAME_Page_MyRootBrowse_Copy_Action)) {
                this.root_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::root_browse_action_link, this::root_browse_action_click));
            }
        } else {
            this.root_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::root_browse_action_link, this::root_browse_action_click));
        }
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.root_browse_form = new FilterForm<>("root_browse_form", this.root_browse_provider);
        body.add(this.root_browse_form);

        this.root_browse_table = new DataTable<>("root_browse_table", this.root_browse_column, this.root_browse_provider, 20);
        this.root_browse_form.add(this.root_browse_table);

        this.createButton = new BookmarkablePageLink<>("createButton", RootGeneratePage.class);
        body.add(this.createButton);

        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (Permission.hasAccess(getSession(), Role.NAME_ROOT, Role.NAME_Page_MyRootBrowse_IssueNewRoot_Action)) {
            } else {
                this.createButton.setVisible(false);
            }
        }
    }

    @Override
    public ItemPanel htmlColumn(String key, IModel<String> display, Tuple object) {
        long uuid = object.get("uuid", long.class);
        String name = StringUtils.replace(object.get("common_name", String.class), " ", "_");
        return new ClickableCell(this::download, object, uuid + "_" + name + ".zip");
    }

    protected void download(Tuple tuple, Link<Void> link) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            Permission.tryAccess(getSession(), Role.NAME_ROOT, Role.NAME_Page_MyRootBrowse_Download_Action);
        }
        try {
            long uuid = tuple.get("uuid", long.class);

            RootRepository rootRepository = context.getBean(RootRepository.class);
            Optional<Root> optionalRoot = rootRepository.findById(uuid);
            Root root = optionalRoot.orElseThrow(() -> new WicketRuntimeException(""));

            String changeit = "changeit";

            String rootName = StringUtils.replace("root-" + root.getCommonName(), " ", "_");

            ByteArrayOutputStream data = new ByteArrayOutputStream();
            ZipArchiveOutputStream zipArchiveOutputStream = new ZipArchiveOutputStream(data);

            {
                ZipArchiveEntry rootEntry = new ZipArchiveEntry(rootName + ".crt");
                rootEntry.setSize(root.getCertificate().getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(rootEntry);
                zipArchiveOutputStream.write(root.getCertificate().getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                StringBuffer buffer = new StringBuffer();
                buffer.append("# JKS entry").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -trustcacerts -keystore " + rootName + ".jks -storepass " + changeit + " -alias " + rootName + " -import -file " + rootName + ".crt").append("\n");
                buffer.append("\n");
                buffer.append("# Create Trust Store P12 File").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("openssl pkcs12 -nokeys -in " + rootName + ".crt -export -out " + rootName + ".p12 -passout pass:" + changeit).append("\n");

                String crt = buffer.toString();
                ZipArchiveEntry caChainEntry = new ZipArchiveEntry("README.txt");
                caChainEntry.setSize(crt.getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(caChainEntry);
                zipArchiveOutputStream.write(crt.getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            zipArchiveOutputStream.close();

            IResourceStream resourceStream = new MemoryResourceStream("application/zip", data.toByteArray());
            getRequestCycle().scheduleRequestHandlerAfterCurrent(
                    new ResourceStreamRequestHandler(resourceStream) {
                        @Override
                        public void respond(IRequestCycle requestCycle) {
                            super.respond(requestCycle);
                        }
                    }.setFileName(uuid + "_" + rootName + ".zip")
                            .setContentDisposition(ContentDisposition.INLINE)
                            .setCacheDuration(Duration.ZERO));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected List<ActionItem> root_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>(0);
        String status = model.get("status", String.class);
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyRootBrowse_Copy_Action)) {
                actions.add(new ActionItem("Copy", Model.of("Copy"), ItemCss.SUCCESS));
            }
        } else {
            actions.add(new ActionItem("Copy", Model.of("Copy"), ItemCss.SUCCESS));
        }
        if (Root.STATUS_GOOD.equals(status)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyRootBrowse_Revoke_Action)) {
                    actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.DANGER));
                }
            } else {
                actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.DANGER));
            }
        }
        return actions;
    }

    protected void root_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if ("Revoke".equals(link)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                Permission.tryAccess(getSession(), Role.NAME_ROOT, Role.NAME_Page_MyRootBrowse_Revoke_Action);
            }
            long uuid = model.get("uuid", long.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(RootRevokePage.class, parameters);
        } else if ("Copy".equals(link)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                Permission.tryAccess(getSession(), Role.NAME_ROOT, Role.NAME_Page_MyRootBrowse_Copy_Action);
            }
            long uuid = model.get("uuid", long.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(RootGeneratePage.class, parameters);
        }
    }

}
