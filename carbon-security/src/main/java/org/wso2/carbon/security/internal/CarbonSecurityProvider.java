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

package org.wso2.carbon.security.internal;

import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.security.BasicAuthenticator;
import org.wso2.carbon.security.CarbonAuthenticator;

/**
 * OSGi service component which handle authentication and authorization
 */
@Component(
        name = "org.wso2.carbon.security.internal.CarbonSecurityProvider",
        immediate = true
)
public class CarbonSecurityProvider {

    private ServiceRegistration<CarbonAuthenticator> serviceRegistration;

    @Activate
    public void registerCarbonAuthenticator(BundleContext bundleContext) {
        serviceRegistration = bundleContext.registerService(CarbonAuthenticator.class,
                                                            new BasicAuthenticator(), null);
    }

    @Deactivate
    public void unregisterCarbonAuthenticator(BundleContext bundleContext) {
        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
    }

}

