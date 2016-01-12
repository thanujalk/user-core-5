package org.wso2.carbon.jaas.authinterceptor;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.mss.HttpResponder;
import org.wso2.carbon.mss.Interceptor;
import org.wso2.carbon.mss.ServiceMethodInfo;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
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

        Subject subject = new Subject();

        //LoginContext loginContext= new LoginContext();

        return (username.equals("root") && password.equals("password"));
    }
}
