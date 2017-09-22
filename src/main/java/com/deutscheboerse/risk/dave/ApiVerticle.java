package com.deutscheboerse.risk.dave;

import com.deutscheboerse.risk.dave.auth.JWKSAuthProviderImpl;
import com.deutscheboerse.risk.dave.config.ApiConfig;
import com.deutscheboerse.risk.dave.healthcheck.HealthCheck;
import com.deutscheboerse.risk.dave.persistence.PersistenceService;
import com.deutscheboerse.risk.dave.restapi.MarginApiFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.ClientAuth;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.*;
import io.vertx.serviceproxy.ProxyHelper;

import java.util.Arrays;
import java.util.stream.Collectors;

import static com.deutscheboerse.risk.dave.healthcheck.HealthCheck.Component.API;

public class ApiVerticle extends AbstractVerticle {
    private static final Logger LOG = LoggerFactory.getLogger(ApiVerticle.class);

    private static final String API_VERSION = "v1.0";
    private static final String API_PREFIX = String.format("/api/%s", API_VERSION);

    private static final Integer MAX_BODY_SIZE = 1024 * 1024; // 1MB

    private static final String HIDDEN_CERTIFICATE = "******************";

    private HttpServer server;

    private ApiConfig config;

    private PersistenceService persistenceProxy;

    @Override
    public void start(Future<Void> startFuture) throws Exception {
        LOG.info("Starting {} with configuration: {}", ApiVerticle.class.getSimpleName(), hideCertificates(config()).encodePrettily());

        config = (new ObjectMapper()).readValue(config().toString(), ApiConfig.class);
        persistenceProxy = ProxyHelper.createProxy(PersistenceService.class, vertx, PersistenceService.SERVICE_ADDRESS);

        HealthCheck healthCheck = new HealthCheck(this.vertx);

        startHttpServer().setHandler(ar -> {
            if (ar.succeeded()) {
                healthCheck.setComponentReady(API);
                startFuture.complete();
            } else {
                healthCheck.setComponentFailed(API);
                startFuture.fail(ar.cause());
            }
        });
    }

    private JsonObject hideCertificates(JsonObject config) {
        JsonObject secretConfig = config.copy();
        secretConfig.getJsonObject("ssl", new JsonObject())
                .put("sslKey", HIDDEN_CERTIFICATE)
                .put("sslCert", HIDDEN_CERTIFICATE)
                .put("sslTrustCerts", new JsonArray(
                        config.getJsonObject("ssl", new JsonObject()).getJsonArray("sslTrustCerts").stream()
                                .map(i -> HIDDEN_CERTIFICATE).collect(Collectors.toList()))
                );
        secretConfig.getJsonObject("csrf", new JsonObject())
                .put("secret", HIDDEN_CERTIFICATE);
        return secretConfig;
    }

    private Future<HttpServer> startHttpServer() {
        Future<HttpServer> webServerFuture = Future.future();
        Future<Void> routerFuture = Future.future();
        Router router = configureRouter(routerFuture);

        routerFuture.compose(i -> {
            HttpServerOptions httpOptions = configureWebServer();
            int port = config.getPort();
            LOG.info("Starting web server on port {}", port);
            server = vertx.createHttpServer(httpOptions)
                    .requestHandler(router::accept)
                    .listen(port, webServerFuture);
        }, webServerFuture);

        return webServerFuture;
    }

    private HttpServerOptions configureWebServer() {
        HttpServerOptions httpOptions = new HttpServerOptions();
        setSsl(httpOptions);
        setCompression(httpOptions);
        return httpOptions;
    }

    private void setSsl(HttpServerOptions httpServerOptions) {
        ApiConfig.SslConfig sslConfig = config.getSsl();
        if (!sslConfig.isEnable()) {
            return;
        }
        httpServerOptions.setSsl(true);
        PemKeyCertOptions pemKeyCertOptions = new PemKeyCertOptions()
                .setKeyValue(Buffer.buffer(sslConfig.getSslKey()))
                .setCertValue(Buffer.buffer(sslConfig.getSslCert()));
        httpServerOptions.setPemKeyCertOptions(pemKeyCertOptions);

        PemTrustOptions pemTrustOptions = new PemTrustOptions();
        Arrays.stream(sslConfig.getSslTrustCerts())
                .map(Object::toString)
                .forEach(trustKey -> pemTrustOptions.addCertValue(Buffer.buffer(trustKey)));
        if (!pemTrustOptions.getCertValues().isEmpty()) {
            httpServerOptions.setPemTrustOptions(pemTrustOptions);
            ClientAuth clientAuth = sslConfig.isSslRequireClientAuth() ?
                    ClientAuth.REQUIRED : ClientAuth.REQUEST;
            httpServerOptions.setClientAuth(clientAuth);
        }
    }

    private void setCompression(HttpServerOptions httpOptions) {
        if (config.isCompression()) {
            LOG.info("Enabling compression on webserver");
            httpOptions.setCompressionSupported(true);
        }
    }

    private Router configureRouter(Handler<AsyncResult<Void>> resultHandler) {
        Router router = Router.router(vertx);

        setCorsHandler(router);
        setAuthHandler(router, resultHandler);

        LOG.info("Adding route REST API");
        router.route(API_PREFIX+"/*").handler(BodyHandler.create());
        router.mountSubRouter(API_PREFIX, MarginApiFactory.accountMarginApi(vertx, persistenceProxy).getRoutes());
        router.mountSubRouter(API_PREFIX, MarginApiFactory.liquiGroupMarginApi(vertx, persistenceProxy).getRoutes());
        router.mountSubRouter(API_PREFIX, MarginApiFactory.liquiGroupSplitMarginApi(vertx, persistenceProxy).getRoutes());
        router.mountSubRouter(API_PREFIX, MarginApiFactory.poolMarginApi(vertx, persistenceProxy).getRoutes());
        router.mountSubRouter(API_PREFIX, MarginApiFactory.positionReportApi(vertx, persistenceProxy).getRoutes());
        router.mountSubRouter(API_PREFIX, MarginApiFactory.riskLimitUtilizationApi(vertx, persistenceProxy).getRoutes());

        return router;
    }

    private void setCorsHandler(Router router) {
        if (config.getCors().isEnable()) {
            LOG.info("Enabling CORS handler");

            //Wildcard(*) not allowed if allowCredentials is true
            CorsHandler corsHandler = CorsHandler.create(config.getCors().getOrigin());
            corsHandler.allowCredentials(false);
            corsHandler.allowedMethod(HttpMethod.OPTIONS);
            corsHandler.allowedMethod(HttpMethod.GET);
            corsHandler.allowedMethod(HttpMethod.POST);
            corsHandler.allowedMethod(HttpMethod.DELETE);
            corsHandler.allowedHeader("Authorization");
            corsHandler.allowedHeader("www-authenticate");
            corsHandler.allowedHeader("Content-Type");

            router.route().handler(corsHandler);
        }
    }

    private void setCsrfHandler(Router router) {
        if (config.getCsrf().isEnable()) {
            LOG.info("Enabling CSRF handler");
            router.route().handler(CookieHandler.create());
            router.route().handler(CSRFHandler.create(config.getCsrf().getSecret()));
        }
    }

    private void setAuthHandler(Router router, Handler<AsyncResult<Void>> resultHandler) {
        if (config.getAuth().isEnable()) {
            LOG.info("Enabling authentication");

            JWKSAuthProviderImpl jwksAuthenticationProvider = new JWKSAuthProviderImpl(vertx, config.getAuth());
            jwksAuthenticationProvider.load(resultHandler);
            router.route(API_PREFIX + "/*").handler(JWTAuthHandler.create(jwksAuthenticationProvider));

            router.route().handler(BodyHandler.create().setBodyLimit(MAX_BODY_SIZE));
            setCsrfHandler(router);
            addSecurityHeaders(router);
        } else {
            resultHandler.handle(Future.succeededFuture());
        }
    }

    private void addSecurityHeaders(Router router) {
        // From http://vertx.io/blog/writing-secure-vert-x-web-apps/
        router.route().handler(ctx ->
        {
            ctx.response()
                    // do not allow proxies to cache the data
                    .putHeader("Cache-Control", "no-store, no-cache")
                    // prevents Internet Explorer from MIME - sniffing a
                    // response away from the declared content-type
                    .putHeader("X-Content-Type-Options", "nosniff")
                    // Strict HTTPS (for about ~6Months)
                    .putHeader("Strict-Transport-Security", "max-age=" + 15768000)
                    // IE8+ do not allow opening of attachments in the context of this resource
                    .putHeader("X-Download-Options", "noopen")
                    // enable XSS for IE
                    .putHeader("X-XSS-Protection", "1; mode=block")
                    // deny frames
                    .putHeader("X-FRAME-OPTIONS", "DENY")
                    .putHeader("Expires", "0");

            ctx.next();
        });
    }

    @Override
    public void stop() throws Exception {
        LOG.info("Shutting down webserver");
        server.close();
    }
}
