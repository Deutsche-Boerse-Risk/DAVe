package com.deutscheboerse.risk.dave;

import ch.qos.logback.classic.Logger;
import com.deutscheboerse.risk.dave.log.TestAppender;
import com.deutscheboerse.risk.dave.model.AccountMarginModel;
import com.deutscheboerse.risk.dave.persistence.EchoPersistenceService;
import com.deutscheboerse.risk.dave.persistence.PersistenceService;
import com.deutscheboerse.risk.dave.persistence.StoreManagerMock;
import com.deutscheboerse.risk.dave.util.URIBuilder;
import com.deutscheboerse.risk.dave.utils.DataHelper;
import com.deutscheboerse.risk.dave.utils.TestConfig;
import com.google.inject.AbstractModule;
import com.google.inject.Singleton;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

@RunWith(VertxUnitRunner.class)
public class MainVerticleTest {
    private static final TestAppender testAppender = TestAppender.getAppender(MainVerticle.class);
    private static final Logger rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

    private Vertx vertx;

    @Before
    public void setUp() {
        this.vertx = Vertx.vertx();
        rootLogger.addAppender(testAppender);
    }

    @Test
    public void testFullChain(TestContext context) throws InterruptedException, UnsupportedEncodingException {
        // Start storage mock
        StoreManagerMock storageMock = new StoreManagerMock(vertx);
        final Async serverStarted = context.async();
        storageMock.listen(context.asyncAssertSuccess(ar -> serverStarted.complete()));

        serverStarted.awaitSuccess(30000);

        // Deploy MainVerticle with default persistence binder (PersistenceBinder)
        DeploymentOptions options = getDeploymentOptions();
        options.getConfig().remove("guice_binder");
        final Async deployAsync = context.async();
        vertx.deployVerticle(MainVerticle.class.getName(), options, context.asyncAssertSuccess(res -> deployAsync.complete()));

        deployAsync.awaitSuccess(30000);

        AccountMarginModel latestModel = DataHelper.getLastModelFromFile(AccountMarginModel.class, 1);
        String uri = new URIBuilder("/api/v1.0/am/latest")
                .addParams(DataHelper.getQueryParams(latestModel))
                .build();

        JsonObject queryParams = DataHelper.getQueryParams(latestModel);
        JsonObject expectedResult = new JsonObject()
                .put("snapshotID", StoreManagerMock.LATEST_SNAPSHOT_ID)
                .put("businessDate", StoreManagerMock.BUSINESS_DATE)
                .put("timestamp", 0)
                .put("clearer", queryParams.getString("clearer"))
                .put("member", queryParams.getString("member"))
                .put("account", queryParams.getString("account"))
                .put("marginCurrency", queryParams.getString("marginCurrency"))
                .put("clearingCurrency", queryParams.getString("clearingCurrency"))
                .put("pool", queryParams.getString("pool"))
                .put("marginReqInMarginCurr", 0.0)
                .put("marginReqInClrCurr", 0.0)
                .put("unadjustedMarginRequirement", 0.0)
                .put("variationPremiumPayment", 0.0);

        final Async asyncRest = context.async();
        HttpClientOptions sslOpts = new HttpClientOptions().setSsl(true)
                .setVerifyHost(false).setPemTrustOptions(TestConfig.HTTP_API_CERTIFICATE.trustOptions());
        vertx.createHttpClient(sslOpts).getNow(TestConfig.API_PORT, "localhost", uri, res -> {
            context.assertEquals(200, res.statusCode());
            res.bodyHandler(body -> {
                try {
                    JsonArray positions = body.toJsonArray();
                    context.assertEquals(1, positions.size());
                    context.assertEquals(expectedResult, positions.getJsonObject(0));
                    asyncRest.complete();
                } catch (Exception e) {
                    context.fail(e);
                }
            });
        });
        asyncRest.awaitSuccess(30000);

        storageMock.close(context.asyncAssertSuccess());
    }

    @Test
    public void testFailedDeployment(TestContext context) {
        DeploymentOptions options = getDeploymentOptions();
        options.getConfig().getJsonObject("api", new JsonObject()).put("port", -1);
        vertx.deployVerticle(MainVerticle.class.getName(), options, context.asyncAssertFailure());
    }

    @Test
    public void testFailedDeploymentWrongConfig(TestContext context) {
        Async mainVerticleAsync = context.async();
        DeploymentOptions options = getDeploymentOptions();
        System.setProperty("dave.configurationFile", "nonexisting");
        this.vertx.deployVerticle(MainVerticle.class.getName(), options, ar -> {
            System.clearProperty("dave.configurationFile");
            if (ar.succeeded()) {
                context.fail(ar.cause());
            } else {
                mainVerticleAsync.complete();
            }
        });
    }

    private DeploymentOptions getDeploymentOptions() {
        JsonObject config = TestConfig.getGlobalConfig();
        config.put("guice_binder", EchoBinder.class.getName());
        return new DeploymentOptions().setConfig(config);
    }

    @After
    public void cleanup(TestContext context) {
        rootLogger.detachAppender(testAppender);
        testAppender.clear();
        this.vertx.close(context.asyncAssertSuccess());
    }

    public static class EchoBinder extends AbstractModule {
        @Override
        protected void configure() {
            bind(PersistenceService.class).to(EchoPersistenceService.class).in(Singleton.class);
        }
    }
}
