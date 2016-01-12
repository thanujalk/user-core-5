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

package org.wso2.carbon.jaas.authinterceptor;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.jaas.callback.BasicAuthCallbackHandler;
import org.wso2.carbon.mss.HttpResponder;
import org.wso2.carbon.mss.Interceptor;
import org.wso2.carbon.mss.ServiceMethodInfo;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.nio.charset.Charset;
import java.util.Base64;

/**
 * Sample Interceptor which logs HTTP headers of the request.
 */
@Component(
        name = "org.wso2.carbon.jaas.authinterceptor.BasicAuthInterceptor",
        service = Interceptor.class,
        immediate = true
)
public class BasicAuthInterceptor implements Interceptor {

    private static final Logger log = LoggerFactory.getLogger(BasicAuthInterceptor.class);

    private static final String AUTH_TYPE_BASIC = "Basic";

    private static final int AUTH_TYPE_BASIC_LENGTH = AUTH_TYPE_BASIC.length();

    @Override
    public boolean preCall(HttpRequest request, HttpResponder responder, ServiceMethodInfo serviceMethodInfo) {

        HttpHeaders headers = request.headers();
        if (headers != null) {
            String authHeader = headers.get(HttpHeaders.Names.AUTHORIZATION);
            if (authHeader != null) {
                String authType = authHeader.substring(0, AUTH_TYPE_BASIC_LENGTH);
                String authEncoded = authHeader.substring(AUTH_TYPE_BASIC_LENGTH).trim();
                if (AUTH_TYPE_BASIC.equals(authType) && !authEncoded.isEmpty()) {
                    byte[] decodedByte = authEncoded.getBytes(Charset.forName("UTF-8"));
                    String authDecoded = new String(Base64.getDecoder().decode(decodedByte), Charset.forName("UTF-8"));
                    String[] authParts = authDecoded.split(":");
                    String username = authParts[0];
                    String password = authParts[1];
                    if (authenticate(username, password)) {
                        return true;
                    }
                }
            }
        }
        Multimap<String, String> map = ArrayListMultimap.create();
        map.put(HttpHeaders.Names.WWW_AUTHENTICATE, AUTH_TYPE_BASIC);
        responder.sendStatus(HttpResponseStatus.UNAUTHORIZED, map);
        return false;
    }

    @Override
    public void postCall(HttpRequest request, HttpResponseStatus status, ServiceMethodInfo serviceMethodInfo) {

    }

    private boolean authenticate(String username, String password) {

        CallbackHandler callbackHandler = new BasicAuthCallbackHandler(username, password.toCharArray());
        LoginContext loginContext = null;
        try {
            loginContext = new LoginContext("", callbackHandler);
        } catch (LoginException e) {
            log.error("Failed to initiate login context", e);
            return false;
        }

        try {
            loginContext.login();
        } catch (LoginException e) {
            log.error("Login failed for user : " + username, e);
            return false;
        }

        return true;
    }
}