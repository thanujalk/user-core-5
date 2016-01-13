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

package org.wso2.carbon.security.jaas.module;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.jaas.pincipal.CarbonPrincipal;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;


/**
 * This  LoginModule authenticates users with a password.
 */
public class BasicAuthLoginModule implements LoginModule {


    private static final String USERNAME = "admin";
    private static final char[] PASSWORD = new char[]{'a', 'd', 'm', 'i', 'n'};
    private static final Logger log = LoggerFactory.getLogger(BasicAuthLoginModule.class);
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map options;
    private boolean succeeded = false;
    private boolean commitSucceeded = false;
    private CarbonPrincipal carbonPrincipal;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
                           Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
    }

    @Override
    public boolean login() throws LoginException {

        Callback[] callbacks = new Callback[2];

        callbacks[0] = new NameCallback("Username");
        callbacks[1] = new PasswordCallback("Password", false);

        try {
            callbackHandler.handle(callbacks);
        } catch (IOException | UnsupportedCallbackException e) {
            log.error("Error while handling callbacks.", e);
            throw new LoginException("Error while handling callbacks.");
        }

        String username = ((NameCallback) callbacks[0]).getName();
        char[] password = ((PasswordCallback) callbacks[1]).getPassword();

        if (USERNAME.equals(username) && Arrays.equals(PASSWORD, password)) {
            succeeded = true;
        } else {
            succeeded = false;
        }
        return succeeded;
    }

    @Override
    public boolean commit() throws LoginException {
        if (succeeded == false) {
            return false;
        } else {
            carbonPrincipal = new CarbonPrincipal();
            if (!subject.getPrincipals().contains(carbonPrincipal)) {
                subject.getPrincipals().add(carbonPrincipal);
            }

            commitSucceeded = true;
            return commitSucceeded;
        }
    }

    @Override
    public boolean abort() throws LoginException {
        return false;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }
}
