/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.broker.saml.mappers;

import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.common.util.CollectionUtil;
import org.keycloak.dom.saml.v2.assertion.*;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.saml.common.util.StringUtil;

import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:jayblanc@gmail.com">Jerome Blanchard</a>
 * Mostly copied from UserAttributeMapper
 * @version $Revision: 1 $
 */
public class UserAttributeX509SubjectNameMapper extends AbstractIdentityProviderMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String SUBJECT_FIELD = "subject.field";
    public static final String USER_ATTRIBUTE = "user.attribute";
    private static final String EMAIL = "email";
    private static final String FIRST_NAME = "firstName";
    private static final String LAST_NAME = "lastName";

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(SUBJECT_FIELD);
        property.setLabel("Subject Field Name");
        property.setHelpText("Name of the field to search for in X509 Subject Name.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(USER_ATTRIBUTE);
        property.setLabel("User Attribute Name");
        property.setHelpText("User attribute name to store field valuemvn .  Use email, lastName, and firstName to map to those predefined user properties.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "saml-user-attribute-x509-subject-idp-mapper";

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "Attribute Importer";
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }
        String subjectField = mapperModel.getConfig().get(SUBJECT_FIELD);
        AssertionType assertion = (AssertionType)context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        SubjectType subject = assertion.getSubject();
        SubjectType.STSubType subType = subject.getSubType();
        NameIDType subjectNameID = (NameIDType) subType.getBaseID();
        Map<String, String> X509SubjectName = Arrays.stream(subjectNameID.getValue().split(","))
          .map(e -> e.trim()).collect(Collectors.toMap(e -> e.substring(0, e.indexOf("=")), e -> e.substring(e.indexOf("=")+1)));

        String fieldValueInContext = X509SubjectName.get(subjectField);
        if (fieldValueInContext != null && !fieldValueInContext.isEmpty()) {
            if (attribute.equalsIgnoreCase(EMAIL)) {
                setIfNotEmpty(context::setLastName, fieldValueInContext);
            } else if (attribute.equalsIgnoreCase(FIRST_NAME)) {
                setIfNotEmpty(context::setLastName, fieldValueInContext);
            } else if (attribute.equalsIgnoreCase(LAST_NAME)) {
                setIfNotEmpty(context::setLastName, fieldValueInContext);
            } else {
                context.setUserAttribute(attribute, fieldValueInContext);
            }
        }
    }

    private void setIfNotEmpty(Consumer<String> consumer, String value) {
        if (value != null && !value.isEmpty()) {
            consumer.accept(value);
        }
    }

    private Predicate<AttributeStatementType.ASTChoiceType> elementWith(String attributeName) {
        return attributeType -> {
            AttributeType attribute = attributeType.getAttribute();
            return Objects.equals(attribute.getName(), attributeName)
                    || Objects.equals(attribute.getFriendlyName(), attributeName);
        };
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
      String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
      if (StringUtil.isNullOrEmpty(attribute)) {
        return;
      }
      String subjectField = mapperModel.getConfig().get(SUBJECT_FIELD);
      AssertionType assertion = (AssertionType)context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
      SubjectType subject = assertion.getSubject();
      SubjectType.STSubType subType = subject.getSubType();
      NameIDType subjectNameID = (NameIDType) subType.getBaseID();
      Map<String, String> X509SubjectName = Arrays.stream(subjectNameID.getValue().split(","))
        .map(e -> e.trim()).collect(Collectors.toMap(e -> e.substring(0, e.indexOf("=")), e -> e.substring(e.indexOf("=")+1)));

      String fieldValueInContext = X509SubjectName.get(subjectField);
        if (attribute.equalsIgnoreCase(EMAIL)) {
            setIfNotEmpty(user::setEmail, fieldValueInContext);
        } else if (attribute.equalsIgnoreCase(FIRST_NAME)) {
            setIfNotEmpty(user::setFirstName, fieldValueInContext);
        } else if (attribute.equalsIgnoreCase(LAST_NAME)) {
            setIfNotEmpty(user::setLastName, fieldValueInContext);
        } else {
            List<String> currentAttributeValues = user.getAttributes().get(attribute);
            if (fieldValueInContext == null) {
                // attribute no longer sent by brokered idp, remove it
                user.removeAttribute(attribute);
            } else if (currentAttributeValues == null) {
                // new attribute sent by brokered idp, add it
                user.setAttribute(attribute, Collections.singletonList(fieldValueInContext));
            } else if (!CollectionUtil.collectionEquals(Collections.singletonList(fieldValueInContext), currentAttributeValues)) {
                // attribute sent by brokered idp has different values as before, update it
                user.setAttribute(attribute, Collections.singletonList(fieldValueInContext));
            }
            // attribute allready set
        }
    }

    @Override
    public String getHelpText() {
        return "Import X509 Subject Name field if it exists in NameID into the specified user property or attribute.";
    }

}
