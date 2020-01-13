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
import org.keycloak.dom.saml.v2.assertion.*;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:jayblanc@gmail.com">Jerome Blanchard</a>
 * Mostly copied from UsernameTemplateMapper
 * @version $Revision: 1 $
 */
public class UsernameX509SubjectNameMapper extends AbstractIdentityProviderMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    public static final String FIELD = "field";

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(FIELD);
        property.setLabel("Field");
        property.setHelpText("Comma separated fields of the X509 Subject to use (first found used) to format the username to import. Typical fields are commonName (CN), serial number (SERIALNUMBER), email (EMAIL), default to all the subjectName");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("EMAIL,CN,SERIALNUMBER");
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "saml-username-x509-subject-idp-mapper";

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
        return "Preprocessor";
    }

    @Override
    public String getDisplayType() {
        return "Username X509 Subject Name Importer";
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType)context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        List<String> fields = Arrays.asList(mapperModel.getConfig().get(FIELD).split(","));
        SubjectType subject = assertion.getSubject();
        SubjectType.STSubType subType = subject.getSubType();
        NameIDType subjectNameID = (NameIDType) subType.getBaseID();
        Map<String, String> X509SubjectName = Arrays.stream(subjectNameID.getValue().split(","))
          .map(e -> e.trim()).collect(Collectors.toMap(e -> e.substring(0, e.indexOf("=")), e -> e.substring(e.indexOf("=")+1)));
        context.setModelUsername(fields.stream().filter(field -> X509SubjectName.containsKey(field)).map(field -> X509SubjectName.get(field)).findFirst().orElse(subjectNameID.getValue()));
    }

    @Override
    public String getHelpText() {
        return "Select X509 Subject Name relevant field for the username to import ";
    }

}
