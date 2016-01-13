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

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.CarbonAuthenticator;
import org.wso2.carbon.security.jaas.callback.BasicAuthCallbackHandler;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;


/**
 * Authentication using Basic HTTP header
 */
public class BasicAuthenticator implements CarbonAuthenticator {


    private static final Logger log = LoggerFactory.getLogger(CarbonAuthenticator.class);

    private static final String AUTH_TYPE_BASIC = "Basic";
    public static final String BASIC_AUTH_CREDENTIALS_SEPERATOR = ":";
    private static final int AUTH_TYPE_BASIC_LENGTH = AUTH_TYPE_BASIC.length();


    @Override
    public boolean authenticate(HttpRequest request) {

        String credentials = extractCredentials(request);

        if (credentials == null) {
            return false;
        }

        String[] authParts = credentials.split(BASIC_AUTH_CREDENTIALS_SEPERATOR);

        String username = authParts[0];
        char[] password;

        if (authParts[1] != null && !authParts[1].isEmpty()) {
            password = authParts[1].toCharArray();
        } else {
            password = new char[0];
        }

        if (authenticate(username, password)) {
            return true;
        }
        return false;
    }

    /**
     *
     * Extract basic auth credentials from HTTP request header.
     *
     * @param request HttpRequest
     * @return credentials String "username:password"
     */
    private String extractCredentials(HttpRequest request) {

        HttpHeaders headers = request.headers();

        if (headers != null) {
            String authHeader = headers.get(HttpHeaders.Names.AUTHORIZATION);
            if (authHeader != null) {
                String authType = authHeader.substring(0, AUTH_TYPE_BASIC_LENGTH);
                String authEncoded = authHeader.substring(AUTH_TYPE_BASIC_LENGTH).trim();
                if (AUTH_TYPE_BASIC.equals(authType) && !authEncoded.isEmpty()) {
                    byte[] decodedByte = authEncoded.getBytes(Charset.forName(StandardCharsets.UTF_8.name()));
                    String authDecoded = new String(Base64.getDecoder().decode(decodedByte),
                                                    Charset.forName(StandardCharsets.UTF_8.name()));
                    return authDecoded;
                }
            }
        } else {
            log.error("HTTP header is 'null'.");
            return null;
        }
        return null;
    }


    /**
     *
     *
     * @param username
     * @param password
     * @return
     */
    private boolean authenticate(String username, char[] password) {

        CallbackHandler callbackHandler = new BasicAuthCallbackHandler(username, password);
        LoginContext loginContext;
        try {
            loginContext = new LoginContext("CarbonBasicAuthLoginConfig", callbackHandler);
        } catch (LoginException e) {
            log.error("Failed to initiate login context", e);
            return false;
        }

        try {
            loginContext.login();
        } catch (LoginException e) {
            log.error("Login failed for user: " + username);
            return false;
        }

        return true;
    }
}
