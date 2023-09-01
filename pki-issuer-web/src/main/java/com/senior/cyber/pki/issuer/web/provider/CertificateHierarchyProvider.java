package com.senior.cyber.pki.issuer.web.provider;

import com.senior.cyber.pki.dao.entity.Certificate;
import com.senior.cyber.pki.dao.enums.CertificateTypeEnum;
import com.senior.cyber.pki.dao.repository.CertificateRepository;
import com.senior.cyber.pki.issuer.web.factory.WicketFactory;
import org.apache.wicket.extensions.markup.html.repeater.util.SortableTreeProvider;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.springframework.context.ApplicationContext;

import java.util.Iterator;
import java.util.List;

public class CertificateHierarchyProvider extends SortableTreeProvider<Certificate, String> {

    @Override
    public Iterator<Certificate> getRoots() {
        ApplicationContext context = WicketFactory.getApplicationContext();
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
        List<Certificate> roots = certificateRepository.findByType(CertificateTypeEnum.Root);
        if (roots == null) {
            return new java.util.ArrayList<Certificate>().listIterator();
        } else {
            return roots.iterator();
        }
    }

    @Override
    public boolean hasChildren(Certificate issuerCertificate) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
        return certificateRepository.existsByIssuerCertificateAndType(issuerCertificate, CertificateTypeEnum.Issuer);
    }

    @Override
    public Iterator<Certificate> getChildren(Certificate issuerCertificate) {
        ApplicationContext context = WicketFactory.getApplicationContext();
        CertificateRepository certificateRepository = context.getBean(CertificateRepository.class);
        List<Certificate> roots = certificateRepository.findByIssuerCertificateAndType(issuerCertificate, CertificateTypeEnum.Issuer);
        if (roots == null) {
            return new java.util.ArrayList<Certificate>().listIterator();
        } else {
            return roots.iterator();
        }
    }

    @Override
    public IModel<Certificate> model(Certificate object) {
        return Model.of(object);
    }

}