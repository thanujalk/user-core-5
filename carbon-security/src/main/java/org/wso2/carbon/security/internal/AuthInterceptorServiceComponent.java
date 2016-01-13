//package org.wso2.carbon.security.internal;
//
//import org.osgi.framework.BundleContext;
//import org.osgi.service.component.annotations.Activate;
//import org.osgi.service.component.annotations.Component;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;
//import org.wso2.carbon.user.core.service.RealmService;
//
///**
// *
// */
//@Component(
//        name = "org.wso2.carbon.jaas.internal.AuthInterceptorServiceComponent",
//        immediate = true,
//        property = {
//                "capability-name=org.wso2.carbon.jaas.authinterceptor.BasicAuthenticator",
//                "component-key=carbon-jaas-interceptor"
//        }
//)
//public class AuthInterceptorServiceComponent implements RequiredCapabilityListener {
//
//    private static final Logger log = LoggerFactory.getLogger(AuthInterceptorServiceComponent.class);
//    private BundleContext bundleContext;
//
//    @Activate
//    protected void start(BundleContext bundleContext) {
//        this.bundleContext = bundleContext;
//        //DataHolder.getInstance().setRuntimeManager(runtimeManager);
//    }
////    protected void activate(ComponentContext context) {
////        if (log.isDebugEnabled()) {
////            log.debug("Auth interceptor service component is activated ");
////        }
////    }
////
////    protected void deactivate(ComponentContext context) {
////        if (log.isDebugEnabled()) {
////            log.debug("Auth interceptor service component is deactivated ");
////        }
////    }
//
////    protected void setRealmService(RealmService realmService) {
////        AuthInterceptorDataHolder.getInstance().setRealmService(realmService);
////    }
//
////    protected void unsetRealmService(RealmService realmService) {
////        AuthInterceptorDataHolder.getInstance().setRealmService(null);
////    }
//
//    @Override
//    public void onAllRequiredCapabilitiesAvailable() {
//        if (log.isDebugEnabled()) {
//            log.debug("Registering RuntimeService as an OSGi service");
//        }
//    }
//}
//
