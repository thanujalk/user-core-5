/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.wso2.carbon.user.api;

/**
 *
 */
public class Properties {
    Property[] mandatoryProperties;
    Property[] optionalProperties;
    Property[] advancedProperties;


    public Property[] getMandatoryProperties() {

        if (mandatoryProperties == null) {
            mandatoryProperties = new Property[0];
        }

        return mandatoryProperties.clone();
    }

    public void setMandatoryProperties(Property[] mandatoryProperties) {
        this.mandatoryProperties = mandatoryProperties.clone();
    }

    public Property[] getOptionalProperties() {

        if (optionalProperties == null) {
            optionalProperties = new Property[0];
        }

        return optionalProperties.clone();
    }

    public void setOptionalProperties(Property[] optionalProperties) {
        this.optionalProperties = optionalProperties.clone();
    }

    public Property[] getAdvancedProperties() {

        if (advancedProperties == null) {
            advancedProperties = new Property[0];
        }

        return advancedProperties.clone();
    }

    public void setAdvancedProperties(Property[] advancedProperties) {
        this.advancedProperties = advancedProperties.clone();
    }
}


