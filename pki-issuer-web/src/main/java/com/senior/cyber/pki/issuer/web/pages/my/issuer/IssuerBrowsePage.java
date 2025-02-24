package com.senior.cyber.pki.issuer.web.pages.my.issuer;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.jackson.CertificateSerializer;
import com.senior.cyber.frmk.common.jakarta.persistence.Sql;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DefaultDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.IColumn;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.cell.ClickableCell;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.*;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.util.AbstractJdbcDataProvider;
import com.senior.cyber.frmk.common.wicket.functional.DeserializerFunction;
import com.senior.cyber.frmk.common.wicket.functional.FilterFunction;
import com.senior.cyber.frmk.common.wicket.functional.HtmlSerializerFunction;
import com.senior.cyber.frmk.common.wicket.functional.SerializerFunction;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Certificate_;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.entity.User;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import com.senior.cyber.pki.dao.repository.UserRepository;
import com.senior.cyber.pki.issuer.web.data.MySqlDataProvider;
import com.senior.cyber.pki.issuer.web.factory.WebSession;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
import com.senior.cyber.pki.issuer.web.pages.MasterPage;
import com.senior.cyber.pki.issuer.web.utility.MemoryResourceStream;
import jakarta.persistence.Tuple;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.extensions.markup.html.repeater.data.sort.SortOrder;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.markup.html.link.Link;
import org.apache.wicket.model.Model;
import org.apache.wicket.request.IRequestCycle;
import org.apache.wicket.request.handler.resource.ResourceStreamRequestHandler;
import org.apache.wicket.request.mapper.parameter.PageParameters;
import org.apache.wicket.request.resource.ContentDisposition;
import org.apache.wicket.util.resource.IResourceStream;
import org.springframework.context.ApplicationContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.*;

@Bookmark("/my/issuer/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyIntermediateBrowse})
public class IssuerBrowsePage extends MasterPage {

    protected Certificate issuerCertificate;

    protected FilterForm intermediate_browse_form;
    protected MySqlDataProvider intermediate_browse_provider;
    protected List<IColumn<Tuple, ? extends Serializable>> intermediate_browse_column;
    protected DataTable<Tuple, Serializable> intermediate_browse_table;

    protected BookmarkablePageLink<Void> createButton;

    @Override
    protected void onInitData() {
        super.onInitData();
        WebSession session = getSession();
        ApplicationContext context = WicketFactory.getApplicationContext();
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);

        UserRepository userRepository = context.getBean(UserRepository.class);
        Optional<User> optionalUser = userRepository.findById(session.getUserId());
        User user = optionalUser.orElseThrow();

        PageParameters parameters = getPage().getPageParameters();
        long serial = parameters.get("serial").toLong(0L);
        Optional<Certificate> optionalIssuerCertificate = certificateRepository.findBySerialAndUser(serial, user);
        this.issuerCertificate = optionalIssuerCertificate.orElse(null);

        List<String> types = new ArrayList<>();
        types.add(CertificateTypeEnum.Issuer.name());
        this.intermediate_browse_provider = new MySqlDataProvider(Sql.table(Certificate_.class));
        this.intermediate_browse_provider.setSort("created", SortOrder.DESCENDING);
        this.intermediate_browse_provider.applyWhere("user", Sql.column(Certificate_.user) + " = :user", Map.of("user", session.getUserId()));
        this.intermediate_browse_provider.applyWhere("type", Sql.column(Certificate_.type) + " IN (:type)", Map.of("type", types));
        if (issuerCertificate != null) {
            this.intermediate_browse_provider.applyWhere("issuerCertificate", Sql.column(Certificate_.issuerCertificate) + " = :issuerCertificate", Map.of("issuerCertificate", issuerCertificate.getId()));
        }

        this.intermediate_browse_provider.applyCount(Sql.column(Certificate_.id));
        this.intermediate_browse_provider.applySelect(String.class, "uuid", Sql.column(Certificate_.id));
        this.intermediate_browse_provider.applySelect(Long.class, "serial", Sql.column(Certificate_.serial));

        this.intermediate_browse_column = new ArrayList<>();

        {
            String label = "Created";
            String key = "created";
            String sql = Sql.column(Certificate_.createdDatetime);
            SerializerFunction<Date> serializer = (Date value) -> {
                if (value == null) {
                    return "";
                } else {
                    return DateFormatUtils.format(value, "dd/MM/yyyy");
                }
            };
            DeserializerFunction<Date> deserializer = (String value) -> {
                if (value == null || value.isEmpty()) {
                    return null;
                } else {
                    try {
                        return DateUtils.parseDate(value, "dd/MM/yyyy");
                    } catch (ParseException e) {
                        throw new WicketRuntimeException(e);
                    }
                }
            };
            FilterFunction<Date> filter = (count, alias, params, filterText) -> {
                params.put(key, deserializer.apply(filterText));
                return List.of(AbstractJdbcDataProvider.WHERE + sql + " = :" + key);
            };
            this.intermediate_browse_column.add(this.intermediate_browse_provider.filteredColumn(Date.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Name";
            String key = "common_name";
            String sql = Sql.column(Certificate_.commonName);
            SerializerFunction<String> serializer = (value) -> value;
            DeserializerFunction<String> deserializer = (value) -> value;
            FilterFunction<String> filter = (count, alias, params, filterText) -> {
                String v = StringUtils.trimToEmpty(deserializer.apply(filterText));
                if (!v.isEmpty()) {
                    params.put(key, v + "%");
                    return List.of(AbstractJdbcDataProvider.WHERE + sql + " LIKE :" + key);
                } else {
                    return null;
                }
            };
            this.intermediate_browse_column.add(this.intermediate_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Valid Until";
            String key = "valid_until";
            String sql = Sql.column(Certificate_.validUntil);
            SerializerFunction<Date> serializer = (Date value) -> {
                if (value == null) {
                    return "";
                } else {
                    return DateFormatUtils.format(value, "dd/MM/yyyy");
                }
            };
            DeserializerFunction<Date> deserializer = (String value) -> {
                if (value == null || value.isEmpty()) {
                    return null;
                } else {
                    try {
                        return DateUtils.parseDate(value, "dd/MM/yyyy");
                    } catch (ParseException e) {
                        throw new WicketRuntimeException(e);
                    }
                }
            };
            FilterFunction<Date> filter = (count, alias, params, filterText) -> {
                params.put(key, deserializer.apply(filterText));
                return List.of(AbstractJdbcDataProvider.WHERE + sql + " = :" + key);
            };
            this.intermediate_browse_column.add(this.intermediate_browse_provider.filteredColumn(Date.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Status";
            String key = "status";
            String sql = Sql.column(Certificate_.status);
            SerializerFunction<String> serializer = (value) -> value;
            DeserializerFunction<String> deserializer = (value) -> value;
            FilterFunction<String> filter = (count, alias, params, filterText) -> {
                String v = StringUtils.trimToEmpty(deserializer.apply(filterText));
                if (!v.isEmpty()) {
                    params.put(key, v + "%");
                    return List.of(AbstractJdbcDataProvider.WHERE + sql + " LIKE :" + key);
                } else {
                    return null;
                }
            };
            this.intermediate_browse_column.add(this.intermediate_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Download";
            String key = "download";
            String sql = Sql.column(Certificate_.serial);
            HtmlSerializerFunction<Long> htmlFunction = (tuple, value) -> {
                return new ClickableCell(this::download, tuple, value + ".zip");
            };
            this.intermediate_browse_column.add(this.intermediate_browse_provider.column(Long.class, Model.of(label), key, sql, htmlFunction));
        }

        this.intermediate_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::intermediate_browse_action_link, this::intermediate_browse_action_click));
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.intermediate_browse_form = new FilterForm("intermediate_browse_form", this.intermediate_browse_provider);
        body.add(this.intermediate_browse_form);

        this.intermediate_browse_table = new DefaultDataTable<>("intermediate_browse_table", this.intermediate_browse_column, this.intermediate_browse_provider, 20);
        this.intermediate_browse_table.addTopToolbar(new FilterToolbar<>(this.intermediate_browse_table, this.intermediate_browse_form));
        this.intermediate_browse_form.add(this.intermediate_browse_table);

        this.createButton = new BookmarkablePageLink<>("createButton", IssuerGeneratePage.class);
        body.add(this.createButton);
    }

    protected void download(Tuple tuple, Link<Void> link) {
        if (getSession().getRoles().hasRole(Role.NAME_ROOT) || getSession().getRoles().hasRole(Role.NAME_Page_MyIntermediateBrowse_Download_Action)) {
        } else {
            throw new WicketRuntimeException("No Permission");
        }
        try {
            long serial = tuple.get("serial", long.class);
            ApplicationContext context = WicketFactory.getApplicationContext();
            CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
            Optional<Certificate> optionalIntermediate = certificateRepository.findBySerial(serial);
            Certificate intermediate = optionalIntermediate.orElseThrow(() -> new WicketRuntimeException("never happen"));

            String name = StringUtils.replace(intermediate.getCommonName(), " ", "_");

            String basename = serial + "";
            String filename = basename + ".zip";

            ByteArrayOutputStream data = new ByteArrayOutputStream();
            ZipArchiveOutputStream zipArchiveOutputStream = new ZipArchiveOutputStream(data);

            {

                String changeit = "changeit";

                StringBuffer buffer = new StringBuffer();

                buffer.append("# Create Trust Store JKS File").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -trustcacerts -keystore " + name + ".jks -storepass " + changeit + " -alias " + name + " -import -file " + name + ".crt").append("\n");
                buffer.append("\n");

                buffer.append("# Create Trust Store P12 File").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -importcert -storetype PKCS12 -keystore " + name + ".p12 -storepass changeit -alias " + name + " -file " + name + ".crt -noprompt").append("\n");
                buffer.append("\n");

                buffer.append("# Installation Instructions for SpringBoot (property)").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("server.ssl.enabled=true").append("\n");
                buffer.append("server.ssl.client-auth=need").append("\n");
                buffer.append("server.ssl.trust-store=/your/path/to/" + name + ".p12").append("\n");
                buffer.append("server.ssl.trust-store-type=PKCS12").append("\n");
                buffer.append("server.ssl.trust-store-password=" + changeit).append("\n");
                buffer.append("\n");

                buffer.append("# Installation Instructions for SpringBoot (yaml)").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("server:").append("\n");
                buffer.append("  ssl:").append("\n");
                buffer.append("    enabled: true").append("\n");
                buffer.append("    client-auth: need").append("\n");
                buffer.append("    trust-store: /your/path/to/" + name + ".p12").append("\n");
                buffer.append("    trust-store-type: PKCS12").append("\n");
                buffer.append("    trust-store-password: " + changeit).append("\n");

                String crt = buffer.toString();
                ZipArchiveEntry caChainEntry = new ZipArchiveEntry(basename + "/" + "README.txt");
                caChainEntry.setSize(crt.getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(caChainEntry);
                zipArchiveOutputStream.write(crt.getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                ZipArchiveEntry certificateEntry = new ZipArchiveEntry(basename + "/" + name + ".crt");
                certificateEntry.setSize(CertificateSerializer.convert(intermediate.getCertificate()).getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(certificateEntry);
                zipArchiveOutputStream.write(CertificateSerializer.convert(intermediate.getCertificate()).getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            zipArchiveOutputStream.close();

            IResourceStream resourceStream = new MemoryResourceStream("application/zip", data.toByteArray());
            getRequestCycle().scheduleRequestHandlerAfterCurrent(new ResourceStreamRequestHandler(resourceStream) {
                @Override
                public void respond(IRequestCycle requestCycle) {
                    super.respond(requestCycle);
                }
            }.setFileName(filename).setContentDisposition(ContentDisposition.INLINE).setCacheDuration(Duration.ZERO));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected List<ActionItem> intermediate_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>(0);
        String status = model.get("status", String.class);
        actions.add(new ActionItem("Copy", Model.of("Copy"), ItemCss.SUCCESS));
        if (CertificateStatusEnum.Good.name().equals(status)) {
            actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.DANGER));
        }
        return actions;
    }

    protected void intermediate_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        if ("Revoke".equals(link)) {
            String uuid = model.get("uuid", String.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(IssuerRevokePage.class, parameters);
        } else if ("Copy".equals(link)) {
            String uuid = model.get("uuid", String.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(IssuerGeneratePage.class, parameters);
        }
    }

}
