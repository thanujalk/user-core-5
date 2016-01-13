/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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


package org.wso2.carbon.security.jaas.pincipal;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class CarbonPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 6056209529374720080L;

    private String tenantDomain;
    private String userStoreDomain;
    private String userName;
    private String authenticatedSubjectIdentifier;
    private String federatedIdPName;
    private boolean isFederatedUser;
    private Map<String, String> userAttributes = new HashMap<>();

    @Override
    public boolean equals(Object another) {

        //TODO
        return (another instanceof CarbonPrincipal);
    }

    @Override
    public String toString() {
        //TODO
        return userName;
    }

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public String getName() {
        return null;
    }


    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public String getUserStoreDomain() {
        return userStoreDomain;
    }

    public void setUserStoreDomain(String userStoreDomain) {
        this.userStoreDomain = userStoreDomain;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getAuthenticatedSubjectIdentifier() {
        return authenticatedSubjectIdentifier;
    }

    public void setAuthenticatedSubjectIdentifier(String authenticatedSubjectIdentifier) {
        this.authenticatedSubjectIdentifier = authenticatedSubjectIdentifier;
    }

    public String getFederatedIdPName() {
        return federatedIdPName;
    }

    public void setFederatedIdPName(String federatedIdPName) {
        this.federatedIdPName = federatedIdPName;
    }

    public boolean isFederatedUser() {
        return isFederatedUser;
    }

    public void setFederatedUser(boolean isFederatedUser) {
        this.isFederatedUser = isFederatedUser;
    }

    public Map<String, String> getUserAttributes() {
        return userAttributes;
    }

    public void setUserAttributes(Map<String, String> userAttributes) {
        this.userAttributes = userAttributes;
    }
}
