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

package org.wso2.carbon.auth.internal;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.security.CarbonAuthenticator;


/**
 * OSGi service component
 */
@Component(
        name = "org.wso2.carbon.auth.internal.AuthInterceptorComponent",
        immediate = true
)
public class AuthInterceptorComponent {

    @Activate
    public void registerCarbonSecurityProvider(BundleContext bundleContext) {
        //TODO
    }

    @Deactivate
    public void unregisterCarbonSecurityProvider(BundleContext bundleContext) {
        //TODO
    }

    @Reference(
            name = "org.wso2.carbon.security.internal.CarbonSecurityProvider",
            service = CarbonAuthenticator.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetCarbonAuthenticator"
    )
    public void setCarbonAuthenticator(CarbonAuthenticator carbonAuthenticator) {
        AuthInterceptorDataHolder.getInstance().setCarbonAuthenticator(carbonAuthenticator);
    }

    public void unsetCarbonAuthenticator(CarbonAuthenticator carbonAuthenticator) {
        AuthInterceptorDataHolder.getInstance().setCarbonAuthenticator(null);
    }

}
