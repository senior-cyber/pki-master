package com.senior.cyber.pki.web.pages.my.certificate;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.AbstractDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.cell.ClickableCell;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.DateConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.LongConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.convertor.StringConvertor;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.translator.IHtmlTranslator;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Intermediate;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.Root;
import com.senior.cyber.pki.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.web.configuration.Mode;
import com.senior.cyber.pki.web.data.MySqlDataProvider;
import com.senior.cyber.pki.web.factory.WebSession;
import com.senior.cyber.pki.web.pages.MasterPage;
import com.senior.cyber.pki.web.repository.CertificateRepository;
import com.senior.cyber.pki.web.utility.MemoryResourceStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.lang3.StringUtils;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Bookmark("/my/certificate/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyCertificateBrowse})
public class CertificateBrowsePage extends MasterPage implements IHtmlTranslator<Tuple> {

    protected FilterForm<Map<String, Expression<?>>> certificate_browse_form;
    protected MySqlDataProvider certificate_browse_provider;
    protected List<IColumn<Tuple, String>> certificate_browse_column;
    protected AbstractDataTable<Tuple, String> certificate_browse_table;

    protected BookmarkablePageLink<Void> createButton;

    @Override
    protected void onInitData() {
        super.onInitData();
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        WebSession session = getSession();
        this.certificate_browse_provider = new MySqlDataProvider("tbl_certificate");
        this.certificate_browse_provider.setSort("certificate_id", SortOrder.DESCENDING);
        if (applicationConfiguration.getMode() == Mode.Individual) {
            this.certificate_browse_provider.applyWhere("user", "user_id = " + session.getUserId());
        }
        this.certificate_browse_provider.setCountField("certificate_id");

        this.certificate_browse_column = new ArrayList<>();
        this.certificate_browse_column.add(Column.normalColumn(Model.of("ID"), "uuid", "certificate_id", this.certificate_browse_provider, new LongConvertor()));
        this.certificate_browse_column.add(Column.normalColumn(Model.of("Name"), "common_name", "common_name", this.certificate_browse_provider, new StringConvertor()));
        this.certificate_browse_column.add(Column.normalColumn(Model.of("Valid Until"), "valid_until", "valid_until", this.certificate_browse_provider, new DateConvertor()));
        this.certificate_browse_column.add(Column.normalColumn(Model.of("Status"), "status", "status", this.certificate_browse_provider, new StringConvertor()));
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_Download_Action)) {
                this.certificate_browse_column.add(Column.normalColumn(Model.of("Download"), "download", "status", this.certificate_browse_provider, new StringConvertor(), this));
            }
        } else {
            this.certificate_browse_column.add(Column.normalColumn(Model.of("Download"), "download", "status", this.certificate_browse_provider, new StringConvertor(), this));
        }
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_Copy_Action) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_Revoke_Action)) {
                this.certificate_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::certificate_browse_action_link, this::certificate_browse_action_click));
            }
        } else {
            this.certificate_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::certificate_browse_action_link, this::certificate_browse_action_click));
        }
    }

    @Override
    public ItemPanel htmlColumn(String key, IModel<String> display, Tuple object) {
        long uuid = object.get("uuid", long.class);
        return new ClickableCell(this::download, object, uuid + ".zip");
    }

    protected void download(Tuple tuple, Link<Void> link) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_Download_Action)) {
            } else {
                throw new WicketRuntimeException("No Permission");
            }
        }
        try {
            long uuid = tuple.get("uuid", long.class);

            CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
            Optional<Certificate> optionalCertificate = certificateRepository.findById(uuid);
            Certificate certificate = optionalCertificate.orElseThrow(() -> new WicketRuntimeException(""));
            Intermediate intermediate = certificate.getIntermediate();
            Root root = intermediate.getRoot();

            String name = StringUtils.replace(certificate.getCommonName(), " ", "_");
            String caChain = name + "_ca-chain.crt";
            String fullChain = name + "_full-chain.crt";
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
                ZipArchiveEntry intermediateEntry = new ZipArchiveEntry(StringUtils.replace("intermediate-" + intermediate.getCommonName(), " ", "_") + ".crt");
                intermediateEntry.setSize(intermediate.getCertificate().getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(intermediateEntry);
                zipArchiveOutputStream.write(intermediate.getCertificate().getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                String crt = intermediate.getCertificate() + root.getCertificate();
                ZipArchiveEntry caChainEntry = new ZipArchiveEntry(caChain);
                caChainEntry.setSize(crt.getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(caChainEntry);
                zipArchiveOutputStream.write(crt.getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                String crt = certificate.getCertificate() + intermediate.getCertificate() + root.getCertificate();
                ZipArchiveEntry caChainEntry = new ZipArchiveEntry(fullChain);
                caChainEntry.setSize(crt.getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(caChainEntry);
                zipArchiveOutputStream.write(crt.getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                StringBuffer buffer = new StringBuffer();
                buffer.append("# Reference OpenSSL command line to create p12/pfx file").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("openssl pkcs12 -inkey " + name + ".pem -in " + fullChain + " -export -out " + name + ".p12 -passout pass:" + changeit).append("\n");
                buffer.append("openssl pkcs12 -inkey " + name + ".pem -in " + fullChain + " -export -out " + name + ".pfx -passout pass:" + changeit).append("\n");
                buffer.append("\n");
                buffer.append("# Installation Instructions for Apache").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("SSLCertificateFile /your/path/to/" + name + ".crt").append("\n");
                buffer.append("SSLCertificateKeyFile /your/path/to/" + name + ".pem").append("\n");
                buffer.append("SSLCertificateChainFile /your/path/to/" + caChain).append("\n");
                buffer.append("\n");
                buffer.append("# Installation Instructions for SpringBoot").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("server.ssl.enabled=true").append("\n");
                buffer.append("server.ssl.key-store=/your/path/to/" + name + ".p12").append("\n");
                buffer.append("server.ssl.key-store-type=PKCS12").append("\n");
                buffer.append("server.ssl.key-store-password=changeit").append("\n");
                buffer.append("\n");
                buffer.append("# Import/Delete JDK-11 cacert entry").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("JAVA_HOME=/your/path/to/jdk11").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -delete -noprompt -alias " + rootName + " -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -trustcacerts -keystore $JAVA_HOME/lib/security/cacerts -storepass " + changeit + " -alias " + rootName + " -import -file " + rootName + ".crt").append("\n");
                buffer.append("\n");
                buffer.append("# Import/Delete JDK-8 cacert entry").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("JAVA_HOME=/your/path/to/jdk8").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -delete -noprompt -alias " + rootName + " -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass changeit").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -trustcacerts -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass " + changeit + " -alias " + rootName + " -import -file " + rootName + ".crt").append("\n");
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

            {
                ZipArchiveEntry certificateEntry = new ZipArchiveEntry(name + ".crt");
                certificateEntry.setSize(certificate.getCertificate().getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(certificateEntry);
                zipArchiveOutputStream.write(certificate.getCertificate().getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            if (certificate.getPrivateKey() != null && !"".equals(certificate.getPrivateKey())) {
                ZipArchiveEntry privateKeyEntry = new ZipArchiveEntry(name + ".pem");
                privateKeyEntry.setSize(certificate.getPrivateKey().getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(privateKeyEntry);
                zipArchiveOutputStream.write(certificate.getPrivateKey().getBytes(StandardCharsets.UTF_8));
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
                    }.setFileName(uuid + ".zip")
                            .setContentDisposition(ContentDisposition.INLINE)
                            .setCacheDuration(Duration.ZERO));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.certificate_browse_form = new FilterForm<>("certificate_browse_form", this.certificate_browse_provider);
        body.add(this.certificate_browse_form);

        this.certificate_browse_table = new DataTable<>("certificate_browse_table", this.certificate_browse_column, this.certificate_browse_provider, 20);
        this.certificate_browse_form.add(this.certificate_browse_table);

        this.createButton = new BookmarkablePageLink<>("createButton", CertificateGeneratePage.class);
        body.add(this.createButton);

        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_IssueNewCertificate_Action)) {
            } else {
                this.createButton.setVisible(false);
            }
        }
    }

    protected List<ActionItem> certificate_browse_action_link(String link, Tuple model) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        List<ActionItem> actions = new ArrayList<>(0);
        String status = model.get("status", String.class);
        if (applicationConfiguration.getMode() == Mode.Enterprise) {
            if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_Copy_Action)) {
                actions.add(new ActionItem("Copy", Model.of("Copy"), ItemCss.SUCCESS));
            }
        } else {
            actions.add(new ActionItem("Copy", Model.of("Copy"), ItemCss.SUCCESS));
        }
        if (Certificate.STATUS_GOOD.equals(status)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_Revoke_Action)) {
                    actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.DANGER));
                }
            } else {
                actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.DANGER));
            }
        }
        return actions;
    }

    protected void certificate_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);
        if ("Revoke".equals(link)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_Revoke_Action)) {
                } else {
                    throw new WicketRuntimeException("No Permission");
                }
            }
            long uuid = model.get("uuid", long.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(CertificateRevokePage.class, parameters);
        } else if ("Copy".equals(link)) {
            if (applicationConfiguration.getMode() == Mode.Enterprise) {
                if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyCertificateBrowse_Copy_Action)) {
                } else {
                    throw new WicketRuntimeException("No Permission");
                }
            }
            long uuid = model.get("uuid", long.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(CertificateGeneratePage.class, parameters);
        }
    }

}
