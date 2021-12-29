package com.senior.cyber.pki.web.factory;

import com.senior.cyber.frmk.common.exception.UnauthorizedInstantiationException;
import org.apache.wicket.Application;
import org.apache.wicket.DefaultExceptionMapper;
import org.apache.wicket.core.request.handler.PageProvider;
import org.apache.wicket.request.IRequestHandler;
import org.apache.wicket.request.mapper.parameter.PageParameters;

public class ExceptionMapper extends DefaultExceptionMapper {

    @Override
    protected IRequestHandler mapExpectedExceptions(Exception e, Application application) {
        if (e instanceof UnauthorizedInstantiationException) {
            PageParameters parameters = new PageParameters();
            parameters.add("role", ((UnauthorizedInstantiationException) e).getRoles());
            parameters.add("page", ((UnauthorizedInstantiationException) e).getClassName());
            PageProvider provider = new PageProvider(Application.get().getApplicationSettings().getAccessDeniedPage(), parameters);
            return createPageRequestHandler(provider);
        } else {
            return super.mapExpectedExceptions(e, application);
        }
    }

}
