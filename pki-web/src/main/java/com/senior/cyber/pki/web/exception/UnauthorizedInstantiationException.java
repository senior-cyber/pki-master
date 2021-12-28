package com.senior.cyber.pki.web.exception;

import org.apache.commons.lang3.StringUtils;
import org.apache.wicket.authorization.AuthorizationException;
import org.apache.wicket.authroles.authorization.strategies.role.annotations.AuthorizeInstantiation;
import org.apache.wicket.request.component.IRequestableComponent;

public class UnauthorizedInstantiationException extends AuthorizationException {

    private String componentClassName;

    private String roles;

    public <T extends IRequestableComponent> UnauthorizedInstantiationException(
            final Class<T> componentClass) {
        if (componentClass == null) {
            this.componentClassName = "";
        } else {
            String[] temps = StringUtils.split(componentClass.getName(), '.');
            for (int i = 0; i < temps.length - 1; i++) {
                temps[i] = temps[i].substring(0, 1);
            }
            this.componentClassName = StringUtils.join(temps, ".");
        }
        AuthorizeInstantiation classAnnotation = componentClass.getAnnotation(AuthorizeInstantiation.class);
        if (classAnnotation != null && classAnnotation.value() != null && classAnnotation.value().length != 0) {
            this.roles = StringUtils.join(classAnnotation.value(), ", ");
        } else {
            this.roles = "";
        }
    }

    public String getComponentClassName() {
        return componentClassName;
    }

    public String getRoles() {
        return roles;
    }

}
