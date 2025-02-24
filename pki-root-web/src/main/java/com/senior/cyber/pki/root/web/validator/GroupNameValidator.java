package com.senior.cyber.pki.root.web.validator;

import com.senior.cyber.pki.dao.entity.Group;
import com.senior.cyber.pki.dao.repository.GroupRepository;
import com.senior.cyber.pki.root.web.factory.WicketFactory;
import org.apache.wicket.validation.IValidatable;
import org.apache.wicket.validation.IValidator;
import org.apache.wicket.validation.ValidationError;
import org.springframework.context.ApplicationContext;

import java.util.Optional;

public class GroupNameValidator implements IValidator<String> {

    private String uuid;

    public GroupNameValidator() {
    }

    public GroupNameValidator(String groupId) {
        this.uuid = groupId;
    }

    @Override
    public void validate(IValidatable<String> validatable) {
        String name = validatable.getValue();
        if (name != null && !name.isEmpty()) {
            ApplicationContext context = WicketFactory.getApplicationContext();
            GroupRepository groupRepository = context.getBean(GroupRepository.class);
            Optional<Group> optionalGroup = groupRepository.findByName(name);
            Group group = optionalGroup.orElse(null);
            if (group != null) {
                if (this.uuid == null) {
                    validatable.error(new ValidationError(name + " is not available"));
                } else if (!group.getId().equals(this.uuid)) {
                    validatable.error(new ValidationError(name + " is not available"));
                }
            }
        }
    }

}
