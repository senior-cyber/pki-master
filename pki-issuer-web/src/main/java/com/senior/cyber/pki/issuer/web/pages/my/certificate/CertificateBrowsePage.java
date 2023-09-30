package com.senior.cyber.pki.issuer.web.pages.my.certificate;

import com.senior.cyber.frmk.common.base.Bookmark;
import com.senior.cyber.frmk.common.base.WicketFactory;
import com.senior.cyber.frmk.common.jackson.CertificateSerializer;
import com.senior.cyber.frmk.common.jackson.PrivateKeySerializer;
import com.senior.cyber.frmk.common.jakarta.persistence.Sql;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.DefaultDataTable;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.IColumn;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.cell.ClickableCell;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.ActionFilteredColumn;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.ActionItem;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.FilterForm;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.data.table.filter.ItemCss;
import com.senior.cyber.frmk.common.wicket.extensions.markup.html.repeater.util.AbstractJdbcDataProvider;
import com.senior.cyber.frmk.common.wicket.functional.DeserializerFunction;
import com.senior.cyber.frmk.common.wicket.functional.FilterFunction;
import com.senior.cyber.frmk.common.wicket.functional.HtmlSerializerFunction;
import com.senior.cyber.frmk.common.wicket.functional.SerializerFunction;
import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.entity.Certificate_;
import com.senior.cyber.pki.dao.entity.Key;
import com.senior.cyber.pki.dao.entity.Role;
import com.senior.cyber.pki.dao.enums.CertificateStatusEnum;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import com.senior.cyber.pki.dao.repository.KeyRepository;
import com.senior.cyber.pki.issuer.web.configuration.ApplicationConfiguration;
import com.senior.cyber.pki.issuer.web.data.MySqlDataProvider;
import com.senior.cyber.pki.issuer.web.factory.WebSession;
import com.senior.cyber.pki.issuer.web.pages.MasterPage;
import com.senior.cyber.pki.issuer.web.pages.csr.CsrGeneratePage;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Bookmark("/my/certificate/browse")
@AuthorizeInstantiation({Role.NAME_ROOT, Role.NAME_Page_MyCertificateBrowse})
public class CertificateBrowsePage extends MasterPage {

    protected FilterForm certificate_browse_form;
    protected MySqlDataProvider certificate_browse_provider;
    protected List<IColumn<Tuple, ? extends Serializable>> certificate_browse_column;
    protected DataTable<Tuple, Serializable> certificate_browse_table;

    @Override
    protected void onInitData() {
        super.onInitData();
        WebSession session = getSession();
        this.certificate_browse_provider = new MySqlDataProvider(Sql.table(Certificate_.class));
        this.certificate_browse_provider.setSort("created", SortOrder.DESCENDING);
        this.certificate_browse_provider.applyWhere("type", Sql.column(Certificate_.type) + " = '" + CertificateTypeEnum.Certificate.name() + "'");
        this.certificate_browse_provider.applyWhere("user", Sql.column(Certificate_.user) + " = '" + session.getUserId() + "'");
        this.certificate_browse_provider.applyCount(Sql.column(Certificate_.id));
        this.certificate_browse_provider.applySelect(String.class, "uuid", Sql.column(Certificate_.id));
        this.certificate_browse_provider.applySelect(Long.class, "serial", Sql.column(Certificate_.serial));

        this.certificate_browse_column = new ArrayList<>();
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
            this.certificate_browse_column.add(this.certificate_browse_provider.filteredColumn(Date.class, Model.of(label), key, sql, serializer, filter, deserializer));
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
            this.certificate_browse_column.add(this.certificate_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
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
            this.certificate_browse_column.add(this.certificate_browse_provider.filteredColumn(Date.class, Model.of(label), key, sql, serializer, filter, deserializer));
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
            this.certificate_browse_column.add(this.certificate_browse_provider.filteredColumn(String.class, Model.of(label), key, sql, serializer, filter, deserializer));
        }
        {
            String label = "Download";
            String key = "download";
            String sql = Sql.column(Certificate_.serial);
            SerializerFunction<Long> serializer = String::valueOf;
            HtmlSerializerFunction<Long> htmlFunction = (tuple, value) -> {
                return new ClickableCell(this::download, tuple, value + ".zip");
            };
            this.certificate_browse_column.add(this.certificate_browse_provider.column(Long.class, Model.of(label), key, sql, serializer, htmlFunction));
        }
        this.certificate_browse_column.add(new ActionFilteredColumn<>(Model.of("Action"), this::certificate_browse_action_link, this::certificate_browse_action_click));
    }

    protected void download(Tuple tuple, Link<Void> link) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        ApplicationConfiguration applicationConfiguration = context.getBean(ApplicationConfiguration.class);

        try {
            long serial = tuple.get("serial", long.class);

            CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
            KeyRepository keyRepository = context.getBean(KeyRepository.class);

            Optional<Certificate> optionalCertificate = certificateRepository.findBySerial(serial);
            Certificate certificate = optionalCertificate.orElseThrow();
            List<Certificate> chain = new ArrayList<>();
            chain.add(certificate);

            while (certificate.getIssuerCertificate() != null) {
                Certificate p = certificate.getIssuerCertificate();
                p = certificateRepository.findById(p.getId()).orElseThrow();
                chain.add(p);
                certificate = p;
            }

            Certificate root = null;
            for (Certificate cert : chain) {
                if (cert.getType() == CertificateTypeEnum.Root) {
                    root = cert;
                    break;
                }
            }

            String name = certificate.getSerial() + "";

            String basename = "bundle-" + name;
            String filename = basename + ".zip";

            String publicCertificate = "/certificate-" + name + ".crt";
            String privateKey = "certificate-" + certificate.getSerial() + "-private-key.pem";
            String opensshPrivateKey = name + "-openssh-private.pem";
            String puttyPrivateKey = name + "-putty-private.ppk";
            String rootChain = "root-" + certificate.getSerial() + "-chain.crt";
            String fullChain = "certificate-" + certificate.getSerial() + "-chain.crt";
            String changeit = "changeit";

            String rootName = "root-" + root.getSerial() + ".crt";

            ByteArrayOutputStream data = new ByteArrayOutputStream();
            ZipArchiveOutputStream zipArchiveOutputStream = new ZipArchiveOutputStream(data);

            {
                // root
                ZipArchiveEntry rootEntry = new ZipArchiveEntry(basename + "/" + rootName);
                rootEntry.setSize(CertificateSerializer.convert(root.getCertificate()).getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(rootEntry);
                zipArchiveOutputStream.write(CertificateSerializer.convert(root.getCertificate()).getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                // intermediate
                for (Certificate intermediate : chain) {
                    if (intermediate.getType() == CertificateTypeEnum.Issuer) {
                        ZipArchiveEntry intermediateEntry = new ZipArchiveEntry(basename + "/intermediate-" + intermediate.getSerial() + ".crt");
                        intermediateEntry.setSize(CertificateSerializer.convert(intermediate.getCertificate()).getBytes(StandardCharsets.UTF_8).length);
                        zipArchiveOutputStream.putArchiveEntry(intermediateEntry);
                        zipArchiveOutputStream.write(CertificateSerializer.convert(intermediate.getCertificate()).getBytes(StandardCharsets.UTF_8));
                        zipArchiveOutputStream.closeArchiveEntry();
                    }
                }
            }

            {
                // intermediate chain
                StringBuilder crt = new StringBuilder();
                for (int index = chain.size() - 1; index >= 0; index--) {
                    Certificate cert = chain.get(index);
                    if (cert.getType() == CertificateTypeEnum.Issuer || cert.getType() == CertificateTypeEnum.Root) {
                        crt.append(CertificateSerializer.convert(cert.getCertificate()));
                    }
                }

                ZipArchiveEntry caChainEntry = new ZipArchiveEntry(basename + "/" + rootChain);
                caChainEntry.setSize(crt.toString().getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(caChainEntry);
                zipArchiveOutputStream.write(crt.toString().getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                // certificate chain
                StringBuilder crt = new StringBuilder();
                for (int index = chain.size() - 1; index >= 0; index--) {
                    Certificate cert = chain.get(index);
                    if (cert.getType() == CertificateTypeEnum.Issuer || cert.getType() == CertificateTypeEnum.Root || cert.getType() == CertificateTypeEnum.Certificate) {
                        crt.append(CertificateSerializer.convert(cert.getCertificate()));
                    }
                }
                ZipArchiveEntry caChainEntry = new ZipArchiveEntry(basename + "/" + fullChain);
                caChainEntry.setSize(crt.toString().getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(caChainEntry);
                zipArchiveOutputStream.write(crt.toString().getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            {
                // certificate
                String text = CertificateSerializer.convert(certificate.getCertificate());
                ZipArchiveEntry certificateEntry = new ZipArchiveEntry(basename + "/" + publicCertificate);
                certificateEntry.setSize(text.getBytes(StandardCharsets.UTF_8).length);
                zipArchiveOutputStream.putArchiveEntry(certificateEntry);
                zipArchiveOutputStream.write(text.getBytes(StandardCharsets.UTF_8));
                zipArchiveOutputStream.closeArchiveEntry();
            }

            if (certificate.getKey() != null) {
                // certificate private key
                Optional<Key> optionalKey = keyRepository.findById(certificate.getKey().getId());
                Key key = optionalKey.orElse(null);
                if (key != null) {
                    String text = PrivateKeySerializer.convert(key.getPrivateKey());
                    ZipArchiveEntry privateKeyEntry = new ZipArchiveEntry(basename + "/" + privateKey);
                    privateKeyEntry.setSize(text.getBytes(StandardCharsets.UTF_8).length);
                    zipArchiveOutputStream.putArchiveEntry(privateKeyEntry);
                    zipArchiveOutputStream.write(text.getBytes(StandardCharsets.UTF_8));
                    zipArchiveOutputStream.closeArchiveEntry();
                }
            }

            {
                StringBuffer buffer = new StringBuffer();
                buffer.append("# Reference OpenSSL command line to create p12/pfx file").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("openssl pkcs12 -inkey " + privateKey + " -in " + fullChain + " -export -out " + name + ".p12 -passout pass:" + changeit).append("\n");
                buffer.append("openssl pkcs12 -inkey " + privateKey + " -in " + fullChain + " -export -out " + name + ".pfx -passout pass:" + changeit).append("\n");
                buffer.append("\n");

                buffer.append("# Installation Instructions for Apache2").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("SSLCertificateFile /your/path/to/" + publicCertificate).append("\n");
                buffer.append("SSLCertificateKeyFile /your/path/to/" + privateKey).append("\n");
                buffer.append("SSLCertificateChainFile /your/path/to/" + rootChain).append("\n");
                buffer.append("\n");

                buffer.append("# Create OpenSSH Key Base Authentication ~/.ssh/authorized_keys").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("cp " + privateKey + " ~/.ssh/id_ecdsa").append("\n");
                buffer.append("chmod 600 ~/.ssh/id_ecdsa").append("\n");
                buffer.append("ssh-keygen -y -f ~/.ssh/id_ecdsa > ~/.ssh/id_ecdsa.pub").append("\n");
                buffer.append("ssh-keygen -p -f ~/.ssh/id_ecdsa").append("\n");
                buffer.append("ssh-copy-id -i ~/.ssh/id_ecdsa.pub {user}@{target-ip}").append("\n");
                buffer.append("\n");

                buffer.append("# Create Putty ppk file").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("# for ubuntu").append("\n");
                buffer.append("sudo apt-get install putty-tools").append("\n");
                buffer.append("# for rhel/centos").append("\n");
                buffer.append("sudo yum install putty").append("\n");
                buffer.append("cp " + privateKey + " " + opensshPrivateKey).append("\n");
                buffer.append("chmod 600 " + opensshPrivateKey).append("\n");
                buffer.append("ssh-keygen -p -f " + opensshPrivateKey).append("\n");
                buffer.append("puttygen " + opensshPrivateKey + " -o " + puttyPrivateKey).append("\n");
                buffer.append("\n");

                buffer.append("# Installation Instructions for GitLab").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append(":/>nano /etc/gitlab/gitlab.rb").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("letsencrypt['enable'] = false").append("\n");
                buffer.append("nginx['ssl_certificate'] = '/etc/gitlab/ssl/" + fullChain + "'").append("\n");
                buffer.append("nginx['ssl_certificate_key'] = '/etc/gitlab/ssl/" + privateKey + "'").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append(":/>cp from to").append("\n");
                buffer.append("====================================================================================").append("\n");
                for (Certificate cert : chain) {
                    if (cert.getType() == CertificateTypeEnum.Root) {
                        buffer.append("cp root-" + cert.getSerial() + ".crt /etc/gitlab/trusted-certs/root-" + cert.getSerial() + ".crt").append("\n");
                    } else if (cert.getType() == CertificateTypeEnum.Issuer) {
                        buffer.append("cp intermediate-" + cert.getSerial() + ".crt /etc/gitlab/trusted-certs/intermediate-" + cert.getSerial() + ".crt").append("\n");
                    }
                }
                buffer.append("\n");

                buffer.append("# Installation Instructions for Tomcat (Http11NioProtocol)").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("<Connector port=\"8443\" protocol=\"org.apache.coyote.http11.Http11NioProtocol\" maxThreads=\"150\" SSLEnabled=\"true\">").append("\n");
                buffer.append("    <SSLHostConfig>").append("\n");
                buffer.append("        <Certificate certificateKeystoreFile=\"conf/" + name + ".p12\" certificateKeystorePassword=\"" + changeit + "\" type=\"RSA\" />").append("\n");
                buffer.append("    </SSLHostConfig>").append("\n");
                buffer.append("</Connector>").append("\n");
                buffer.append("\n");

                buffer.append("# Installation Instructions for Tomcat (Http11AprProtocol)").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("<Connector port=\"8443\" protocol=\"org.apache.coyote.http11.Http11AprProtocol\" maxThreads=\"150\" SSLEnabled=\"true\" >").append("\n");
                buffer.append("    <UpgradeProtocol className=\"org.apache.coyote.http2.Http2Protocol\" />").append("\n");
                buffer.append("    <SSLHostConfig>").append("\n");
                buffer.append("        <Certificate certificateKeyFile=\"conf/" + privateKey + "\" certificateFile=\"conf/" + publicCertificate + "\" certificateChainFile=\"conf/" + fullChain + "\" type=\"RSA\" />").append("\n");
                buffer.append("    </SSLHostConfig>").append("\n");
                buffer.append("</Connector>").append("\n");
                buffer.append("\n");

                buffer.append("# Installation Instructions for SpringBoot (property)").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("server.ssl.enabled=true").append("\n");
                buffer.append("server.ssl.key-store=/your/path/to/" + name + ".p12").append("\n");
                buffer.append("server.ssl.key-store-type=PKCS12").append("\n");
                buffer.append("server.ssl.key-store-password=" + changeit).append("\n");
                buffer.append("\n");

                buffer.append("# Installation Instructions for SpringBoot (yaml)").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("server:").append("\n");
                buffer.append("  ssl:").append("\n");
                buffer.append("    enabled: true").append("\n");
                buffer.append("    key-store: /your/path/to/" + name + ".p12").append("\n");
                buffer.append("    key-store-type: PKCS12").append("\n");
                buffer.append("    key-store-password: " + changeit).append("\n");
                buffer.append("\n");

                buffer.append("# Import/Delete JDK-11 RootCA entry").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("JAVA_HOME=/your/path/to/jdk11").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -delete -noprompt -alias " + rootName + " -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -trustcacerts -keystore $JAVA_HOME/lib/security/cacerts -storepass " + changeit + " -alias " + rootName + " -import -file " + rootName + ".crt").append("\n");
                buffer.append("\n");

                buffer.append("# Import/Delete JDK-8 RootCA entry").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("JAVA_HOME=/your/path/to/jdk8").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -delete -noprompt -alias " + rootName + " -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass changeit").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -trustcacerts -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass " + changeit + " -alias " + rootName + " -import -file " + rootName + ".crt").append("\n");
                buffer.append("\n");

                buffer.append("# Create RootCA Trust Store P12 File").append("\n");
                buffer.append("====================================================================================").append("\n");
                buffer.append("$JAVA_HOME/bin/keytool -importcert -storetype PKCS12 -keystore " + rootName + ".p12 -storepass changeit -alias " + rootName + " -file " + rootName + ".crt -noprompt").append("\n");
                ;
                buffer.append("\n");

                String crt = buffer.toString();
                ZipArchiveEntry caChainEntry = new ZipArchiveEntry(basename + "/" + "README.txt");
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
                    }.setFileName(filename)
                            .setContentDisposition(ContentDisposition.INLINE)
                            .setCacheDuration(Duration.ZERO));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void onInitHtml(MarkupContainer body) {
        this.certificate_browse_form = new FilterForm("certificate_browse_form", this.certificate_browse_provider);
        body.add(this.certificate_browse_form);

        this.certificate_browse_table = new DefaultDataTable<>("certificate_browse_table", this.certificate_browse_column, this.certificate_browse_provider, 20);
        this.certificate_browse_form.add(this.certificate_browse_table);
    }

    protected List<ActionItem> certificate_browse_action_link(String link, Tuple model) {
        List<ActionItem> actions = new ArrayList<>(0);
        String status = model.get("status", String.class);
        actions.add(new ActionItem("Copy", Model.of("Copy"), ItemCss.SUCCESS));
        if (CertificateStatusEnum.Good.name().equals(status)) {
            actions.add(new ActionItem("Revoke", Model.of("Revoke"), ItemCss.DANGER));
        }
        return actions;
    }

    protected void certificate_browse_action_click(String link, Tuple model, AjaxRequestTarget target) {
        if ("Revoke".equals(link)) {
            String uuid = model.get("uuid", String.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(CertificateRevokePage.class, parameters);
        } else if ("Copy".equals(link)) {
            String uuid = model.get("uuid", String.class);
            PageParameters parameters = new PageParameters();
            parameters.add("uuid", uuid);
            setResponsePage(CsrGeneratePage.class, parameters);
        }
    }

}
