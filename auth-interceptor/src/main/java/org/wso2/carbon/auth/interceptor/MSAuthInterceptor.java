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

package org.wso2.carbon.auth.interceptor;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.auth.internal.AuthInterceptorDataHolder;
import org.wso2.carbon.mss.HttpResponder;
import org.wso2.carbon.mss.Interceptor;
import org.wso2.carbon.mss.ServiceMethodInfo;
import org.wso2.carbon.security.CarbonAuthenticator;

/**
 *
 */
@Component(
        name = "org.wso2.carbon.auth.interceptor.MSAuthInterceptor",
        service = Interceptor.class,
        immediate = true
)
public class MSAuthInterceptor implements Interceptor {

    @Override
    public boolean preCall(HttpRequest httpRequest, HttpResponder httpResponder, ServiceMethodInfo serviceMethodInfo) {

        CarbonAuthenticator authenticator = AuthInterceptorDataHolder.getInstance().getCarbonAuthenticator();

        if (authenticator != null) {
            if (authenticator.authenticate(httpRequest)) {
                return true;
            } else {
                Multimap<String, String> map = ArrayListMultimap.create();
                map.put(HttpHeaders.Names.WWW_AUTHENTICATE, "Basic");
                httpResponder.sendStatus(HttpResponseStatus.UNAUTHORIZED, map);
                return false;
            }
        } else {
            httpResponder.sendStatus(HttpResponseStatus.INTERNAL_SERVER_ERROR, ArrayListMultimap.create());
            return false;
        }
    }

    @Override
    public void postCall(HttpRequest httpRequest, HttpResponseStatus httpResponseStatus,
                         ServiceMethodInfo serviceMethodInfo) {

    }
}
