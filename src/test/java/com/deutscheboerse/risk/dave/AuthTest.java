package com.deutscheboerse.risk.dave;

import com.deutscheboerse.risk.dave.auth.JWKSAuthProviderImpl;
import com.deutscheboerse.risk.dave.healthcheck.HealthCheck;
import com.deutscheboerse.risk.dave.persistence.EchoPersistenceService;
import com.deutscheboerse.risk.dave.persistence.PersistenceService;
import com.deutscheboerse.risk.dave.utils.TestConfig;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.serviceproxy.ProxyHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

@RunWith(VertxUnitRunner.class)
public class AuthTest {
    private static Vertx vertx;
    private static PersistenceService persistenceProxy;

    private static final String CERTS_VALID = "certs.valid";
    private static final String CERTS_INVALID = "certs.invalid";
    private static final String JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNQjFJZjk4R1lZS0Z2WmFxamdzUHVrMXVlamx6WGhFVXRkbGtEZGU0NFcwIn0.eyJqdGkiOiI1MWFlOWVhNS00NWNiLTQ3MzYtODk3NC0wYWE5NjBmYTQ3ZDIiLCJleHAiOjIxNDc0MTE5NTMsIm5iZiI6MCwiaWF0IjoxNTAyMzQ5NTUzLCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiMjAyLWUzYmNiZjA4NGEyNWIyZWUxZGQtMzhlNDQ0NWMiLCJhdXRoX3RpbWUiOjE1MDIzNDk1NTAsInNlc3Npb25fc3RhdGUiOiJmYTA2OWEzYS1kY2U4LTRkZjUtOTY3NC04NTA5MzAwOWJlYWEiLCJhY3IiOiIxIiwiZnlpIjoiUGxlYXNlIHJlZ2VuZXJhdGUgb24gTW9uZGF5LCBKYW51YXJ5IDE4LCAyMDM4IiwibmFtZSI6IkRBVmUgUmlza0lUIiwiZ2l2ZW5fbmFtZSI6IkRBVmUiLCJmYW1pbHlfbmFtZSI6IlJpc2tJVCIsImVtYWlsIjoicmlza2l0YnJvd3NlcnN0YWNrQGRldXRzY2hlLWJvZXJzZS5jb20iLCJ1c2VybmFtZSI6ImRhdmUifQ.dC5Cdx09dv6SDQJEm6ke4qRJ17zHlflz4lGMkzGai7Zl_YqNdLOrOJudtE8iATmWZBJ68RF4yDiGloBPiq2oFfO2aScaW8xpXp5_8_ILlL9baKFcxuHpqgyE2be4Q-oSJZIaEYWB3c8fYrImOVuBRrhtjV39G5DXTUo4_f6Ff_B9nuaTozr6QfXiQ3DwmZ80oqw19oKzhrDU0mjLsUtc7iQm7_h8rHz_Ps_F3Me7DmmYdhewcMRKWO9tf82-BchDOvv-2qP1ePrFTHfi8zBE5AFxyB11Y1wsMemCzNk_37g6JbjmlJRSiu8neWZYiqkRmg__r6-nv0fc2xxFAyC0Xg";
    private static final String INVALID_JWT_TOKEN = "eyJqdGkiOiI1MWFlOWVhNS00NWNiLTQ3MzYtODk3NC0wYWE5NjBmYTQ3ZDIiLCJleHAiOjIxNDc0MTE5NTMsIm5iZiI6MCwiaWF0IjoxNTAyMzQ5NTUzLCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiMjAyLWUzYmNiZjA4NGEyNWIyZWUxZGQtMzhlNDQ0NWMiLCJhdXRoX3RpbWUiOjE1MDIzNDk1NTAsInNlc3Npb25fc3RhdGUiOiJmYTA2OWEzYS1kY2U4LTRkZjUtOTY3NC04NTA5MzAwOWJlYWEiLCJhY3IiOiIxIiwiZnlpIjoiUGxlYXNlIHJlZ2VuZXJhdGUgb24gTW9uZGF5LCBKYW51YXJ5IDE4LCAyMDM4IiwibmFtZSI6IkRBVmUgUmlza0lUIiwiZ2l2ZW5fbmFtZSI6IkRBVmUiLCJmYW1pbHlfbmFtZSI6IlJpc2tJVCIsImVtYWlsIjoicmlza2l0YnJvd3NlcnN0YWNrQGRldXRzY2hlLWJvZXJzZS5jb20iLCJ1c2VybmFtZSI6ImRhdmUifQ.dC5Cdx09dv6SDQJEm6ke4qRJ17zHlflz4lGMkzGai7Zl_YqNdLOrOJudtE8iATmWZBJ68RF4yDiGloBPiq2oFfO2aScaW8xpXp5_8_ILlL9baKFcxuHpqgyE2be4Q-oSJZIaEYWB3c8fYrImOVuBRrhtjV39G5DXTUo4_f6Ff_B9nuaTozr6QfXiQ3DwmZ80oqw19oKzhrDU0mjLsUtc7iQm7_h8rHz_Ps_F3Me7DmmYdhewcMRKWO9tf82-BchDOvv-2qP1ePrFTHfi8zBE5AFxyB11Y1wsMemCzNk_37g6JbjmlJRSiu8neWZYiqkRmg__r6-nv0fc2xxFAyC0Xg";
    private static final String INVALID_KID_JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNQjFJZjlEZGU0NFcwIn0.eyJqdGkiOiIzNDUxMzI2YS0yY2NhLTRjMTgtOTc4Yy01ZGI4ZGJmYzliZDEiLCJleHAiOjE1MDI0NTM1MDIsIm5iZiI6MCwiaWF0IjoxNTAyNDUxNzAyLCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiZjcyLWM3YWJlMzFjNGMwNDhjMGM1YWMtNjNlMTQ1ZTMiLCJhdXRoX3RpbWUiOjE1MDI0NDQ3MzksInNlc3Npb25fc3RhdGUiOiIwMjIyMDAxZi02ZmZjLTQwNWQtYjEyZi01MGE4NDhlYTRmMTMiLCJhY3IiOiIxIiwibmFtZSI6IkRBVmUgUmlza0lUIiwiZ2l2ZW5fbmFtZSI6IkRBVmUiLCJmYW1pbHlfbmFtZSI6IlJpc2tJVCIsImVtYWlsIjoicmlza2l0YnJvd3NlcnN0YWNrQGRldXRzY2hlLWJvZXJzZS5jb20iLCJ1c2VybmFtZSI6ImRhdmUifQ.HozGG5FVA5zBLnBPjvIGcIUCSdGwyf_a3gRtxHVslnAPTbO2iFqGT4lSx_Pdiu5q_JltV4ffckGDTzT3-s8PPIeO9q5hQLPj0KdHSi21K0KuYBBYNF2r8kszgQjpkAi1uD8tDMAuAnQ0-SpZArqRcsIybKqD8DeKYGNc5Op6dTZYl5YQGCqDV7pOooxQ6GrrQUv64GU421j7F5dTEs2Fq1TWX9uO0yDB3YLDtni_zqYaJhrk2JMF7MxwrM-EMn4S9qhUgiEz2Yt71Ho6JtLBKKV_keAaqB25SckbrCGPzOOJTtbvtEkjo18FwLTjx12vdib-htu-XlgJsnobubEb6w";
    private static final String NO_KID_JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIn0.eyJqdGkiOiIzNDUxMzI2YS0yY2NhLTRjMTgtOTc4Yy01ZGI4ZGJmYzliZDEiLCJleHAiOjE1MDI0NTM1MDIsIm5iZiI6MCwiaWF0IjoxNTAyNDUxNzAyLCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiZjcyLWM3YWJlMzFjNGMwNDhjMGM1YWMtNjNlMTQ1ZTMiLCJhdXRoX3RpbWUiOjE1MDI0NDQ3MzksInNlc3Npb25fc3RhdGUiOiIwMjIyMDAxZi02ZmZjLTQwNWQtYjEyZi01MGE4NDhlYTRmMTMiLCJhY3IiOiIxIiwibmFtZSI6IkRBVmUgUmlza0lUIiwiZ2l2ZW5fbmFtZSI6IkRBVmUiLCJmYW1pbHlfbmFtZSI6IlJpc2tJVCIsImVtYWlsIjoicmlza2l0YnJvd3NlcnN0YWNrQGRldXRzY2hlLWJvZXJzZS5jb20iLCJ1c2VybmFtZSI6ImRhdmUifQ.HozGG5FVA5zBLnBPjvIGcIUCSdGwyf_a3gRtxHVslnAPTbO2iFqGT4lSx_Pdiu5q_JltV4ffckGDTzT3-s8PPIeO9q5hQLPj0KdHSi21K0KuYBBYNF2r8kszgQjpkAi1uD8tDMAuAnQ0-SpZArqRcsIybKqD8DeKYGNc5Op6dTZYl5YQGCqDV7pOooxQ6GrrQUv64GU421j7F5dTEs2Fq1TWX9uO0yDB3YLDtni_zqYaJhrk2JMF7MxwrM-EMn4S9qhUgiEz2Yt71Ho6JtLBKKV_keAaqB25SckbrCGPzOOJTtbvtEkjo18FwLTjx12vdib-htu-XlgJsnobubEb6w";
    private static final String EXPIRED_JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNQjFJZjk4R1lZS0Z2WmFxamdzUHVrMXVlamx6WGhFVXRkbGtEZGU0NFcwIn0.eyJqdGkiOiJhNTgxZGQwYy00OTcyLTQyNDUtYTlhZC04ZDBkN2JjYWJkZGUiLCJleHAiOjE1MDIzNzU0NzUsIm5iZiI6MCwiaWF0IjoxNTAyMzc1MzU1LCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiMGQzLTFhYTFlYmU3NDM5M2JhOWU3N2EtZjU2ODQwOWIiLCJhdXRoX3RpbWUiOjE1MDIzNzUzNTEsInNlc3Npb25fc3RhdGUiOiIzMjg0NmIyZS03MjEzLTQ4OTgtYTIzYS03NWY2OTE5NTNhYzYiLCJhY3IiOiIxIiwibmFtZSI6IkRBVmUgUmlza0lUIiwiZ2l2ZW5fbmFtZSI6IkRBVmUiLCJmYW1pbHlfbmFtZSI6IlJpc2tJVCIsImVtYWlsIjoicmlza2l0YnJvd3NlcnN0YWNrQGRldXRzY2hlLWJvZXJzZS5jb20iLCJ1c2VybmFtZSI6ImRhdmUifQ.bXMW01YDxXSVrsEawKHlZu3H7lVaeSEKFzjjLhacBtNARQJyXo-Po0Ia6b3GwXuwl3TC8E_CBBsxSWFioAXxYlieP9L1paTl3jYeZJZCz63dA7E7J3l_IcpAujH5gDA8ZfCrVjQ83xNN7R61PTCNCN4s1s3wXc7d4CGPslyZZj7H6HFDDB-nYJj_KE6RoB7j6h1nFT8HG51Lodp65a5JDVTWiN4omwe-Yd6SyX2VcQWtM4HocXrfQ2ZHkdn16HboF2CmKRuhucNw05IVKfHViyFMF7haUMRrrOZsUvMqbRIf2odwZ5QvkTctnwGpLBqgXcx6U-MA59zpo_1SQAwfKA";
    private static final String INVALID_ISSUER_JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNQjFJZjk4R1lZS0Z2WmFxamdzUHVrMXVlamx6WGhFVXRkbGtEZGU0NFcwIn0.eyJqdGkiOiI0NDU0YjlmMy05ZjgyLTQ5MzEtYTY2Yi0zYmJkMjMzZmQ0MGMiLCJleHAiOjIxMzg4NzU0MjEsIm5iZiI6MCwiaWF0IjoxNTAyNDUzMDIxLCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiNTVmLTA5YjU0NjQ2NDkxZmFlNjY2YjYtOGNmMjQ4NzAiLCJhdXRoX3RpbWUiOjE1MDI0NTI4ODgsInNlc3Npb25fc3RhdGUiOiI2MmFiZjNhOC1lODliLTRiNjUtOGMxZC1kYTc4MDhkYzdlZWMiLCJhY3IiOiIwIiwiaXNzIjoiU29tZSBpc3MiLCJuYW1lIjoiREFWZSBSaXNrSVQiLCJnaXZlbl9uYW1lIjoiREFWZSIsImZhbWlseV9uYW1lIjoiUmlza0lUIiwiZW1haWwiOiJyaXNraXRicm93c2Vyc3RhY2tAZGV1dHNjaGUtYm9lcnNlLmNvbSIsInVzZXJuYW1lIjoiZGF2ZSJ9.JiiBGG2-dcy3N3kFPDa2H8a9AAH_8PwkTFQMKOMHYo_7rIO_KMfmWrsQk8LYX2ysEazYagAyyzF7CsGe6080oe2amcnsQAuZWMySaPAh95zZoooBKOGPNHkbeMRRb0Virry_kxJ6GMwybhugsBLNp7OE9jVolJTc-wj8E3qSBg-se6yJdQu8sT7WU_IyHpdCxXCNbRQ3wdMjm13g1OyCiWHl2WFzrftwK1LMOARURDiQwGOtG_s6RzlXQked77lIqclHdiZH-PwMGuPo-Ybg4HjLR9zoxEvPd8RPmzg9qV6zKwC3pPSSplNp_aWQ1RwdhhvbIId6EB0333g--yyHKQ";
    private static final String INVALID_AUD_JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNQjFJZjk4R1lZS0Z2WmFxamdzUHVrMXVlamx6WGhFVXRkbGtEZGU0NFcwIn0.eyJqdGkiOiJmMmE3OWYyMy03ZWViLTRmYjYtOTZkMS1kOWQzODZjMmMxMGYiLCJleHAiOjIxMzg4NzU1NjksIm5iZiI6MCwiaWF0IjoxNTAyNDUzMTY5LCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiNDgxLWE5OWI1ZGMxNGE4ZGFmNGJhMDEtMzVmYzRjYjIiLCJhdXRoX3RpbWUiOjE1MDI0NTMxNjUsInNlc3Npb25fc3RhdGUiOiIwMzUzYTMwZC1lNjI3LTQ1ODYtYTA4My1hYWY1NjZhNjNkOWQiLCJhY3IiOiIxIiwiYXVkIjoiVGVzdCBhdWQiLCJuYW1lIjoiREFWZSBSaXNrSVQiLCJnaXZlbl9uYW1lIjoiREFWZSIsImZhbWlseV9uYW1lIjoiUmlza0lUIiwiZW1haWwiOiJyaXNraXRicm93c2Vyc3RhY2tAZGV1dHNjaGUtYm9lcnNlLmNvbSIsInVzZXJuYW1lIjoiZGF2ZSJ9.cHOxWS5WhX7SgLbj0RJakvudtwjzEp72hyKX0-QfM9CeKeTwbKZiaUTOqypsMrK9yJ1FLcFfL45ZTdVRbSnYyrpcFioFS1g4K_3VSnd28ytksfnjkGWnXnmCEoMw1ke7gPtzOYiVKbaBTYfsH2GHOeDgwH2nNaWloFrdZXOOsyVxhCuDoYe6Mo5rt9leMbOvknbFTUf17ugW8DnRWR5MHSwICK602RbDklw1fGtu1l9vPGD1JN-kzDHPuo1joFlABRikGEz6bj1kmAJSA5rv2G-1a1rfIfO2tmrM9u65gL_Rc422wPb3ITCxcDNbGxajBQRYURIDJPaCTOJTK7LgWw";
    private static final String INVALID_AUD_ARRAY_JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNQjFJZjk4R1lZS0Z2WmFxamdzUHVrMXVlamx6WGhFVXRkbGtEZGU0NFcwIn0.eyJqdGkiOiJhZGNjMDc1ZC0xYTZjLTQ5NzMtYWZjZC04MjcwNTZkOTA2YmMiLCJleHAiOjIxMzg4NzgwNjQsIm5iZiI6MCwiaWF0IjoxNTAyNDU1NjY0LCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiZGEzLWY3ODVlMmVhNGQyOTkwMzQ5MWEtNTA3NTQ1ZTIiLCJhdXRoX3RpbWUiOjE1MDI0NTU2MDYsInNlc3Npb25fc3RhdGUiOiJhOGQzMThhZS1jMTZjLTQ3YmUtYjE2Ni0zMGFjZjUyMjU0OGQiLCJhY3IiOiIwIiwiYXVkIjpbInNvbWUtb3RoZXIiXSwibmFtZSI6IkRBVmUgUmlza0lUIiwiZ2l2ZW5fbmFtZSI6IkRBVmUiLCJmYW1pbHlfbmFtZSI6IlJpc2tJVCIsImVtYWlsIjoicmlza2l0YnJvd3NlcnN0YWNrQGRldXRzY2hlLWJvZXJzZS5jb20iLCJ1c2VybmFtZSI6ImRhdmUifQ.dK9GNxzZN4Nmq8Id1OChv_4lYdWn_beUZmWK-QKdCo-i_MMSukVZb_tCVfM0q9_63DZN_XG3nBlp8BZXk5zrqijBE9Vd7NxgllgPnbr1EXJvOYpydVRGcy4ftSj2NMWbByTAPfiVj9ZkUUE3c0Prk3xs8t1RM-pB5pwOpCA4Eh7yLbo1D8Af2oJaH5PwKLqzLBQm7gfcPJVYRD_yOzrOssrnwMho-UWCe70iE7VNTxAZG87jzPciek0BhB9MtTiC5Yt2b56b3CEYrjCq1GEsO7yDNcNiJ_YvWGBH0tZtL1nzDK7rZvlaqC1Qsc1Y6wLZm0LsZP6iN1MmgqrkeuLIQw";
    private static final String INVALID_AUD_AZP_JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJNQjFJZjk4R1lZS0Z2WmFxamdzUHVrMXVlamx6WGhFVXRkbGtEZGU0NFcwIn0.eyJqdGkiOiI2NTIxYTFjYy1hZTI3LTRjNTUtYmZkNC1lNTc2YWQ3MDNjYzkiLCJleHAiOjIxMzg4NzgwMDksIm5iZiI6MCwiaWF0IjoxNTAyNDU1NjA5LCJpc3MiOiJodHRwczovL2F1dGguZGF2ZS5kYmctZGV2b3BzLmNvbS9hdXRoL3JlYWxtcy9EQVZlIiwiYXVkIjoiZGF2ZS11aSIsInN1YiI6IjEwNDNmNmZkLTliMjUtNGI4Zi05NDhiLTc2MjIxOWY1NWEzZSIsInR5cCI6IklEIiwiYXpwIjoiZGF2ZS11aSIsIm5vbmNlIjoiZGI0LTU1ODRmZTYwNDM0OGJiZjgwYTctNDg3YzRiYzIiLCJhdXRoX3RpbWUiOjE1MDI0NTU2MDYsInNlc3Npb25fc3RhdGUiOiJhOGQzMThhZS1jMTZjLTQ3YmUtYjE2Ni0zMGFjZjUyMjU0OGQiLCJhY3IiOiIxIiwiYXVkIjpbImRhdmUtdWkiXSwiYXpwIjoic29tZS1vdGhlciIsIm5hbWUiOiJEQVZlIFJpc2tJVCIsImdpdmVuX25hbWUiOiJEQVZlIiwiZmFtaWx5X25hbWUiOiJSaXNrSVQiLCJlbWFpbCI6InJpc2tpdGJyb3dzZXJzdGFja0BkZXV0c2NoZS1ib2Vyc2UuY29tIiwidXNlcm5hbWUiOiJkYXZlIn0.lLfsYFjWIjoEdl5xU1caxDTZICqUzWhpKNYvOrj1ggv58va3w1fxNu9PhkaIWKi2eNa7X36tmbeTZJmHmKHVs0euqYitwKZi6ci4iuxtN1APCBQYu6vy8iNGY2k0q9UcGldJHlPHCPyblccr-TYJpniJqI3exWrhS8Erfw_IYCSNruxeWB-KsB7aMUPH21ObBQKRLVPYumPPg4asv1BDaeCVytw46sfFtcKF9xz9DmloLdz8ulx0HqvnpyuXoqctVfXTPJC3_dWvfIxD9oUunlotXBmOjvuSfSnrvhI4dlrSVLv7_TMQzeivBtkVooPIfuJdlkq_aiW3NFvEIuxNpA";

    @BeforeClass
    public static void setUp() throws IOException {
        AuthTest.vertx = Vertx.vertx();
    }

    private void deployApiVerticle(TestContext context, JsonObject config) {
        final Async asyncStart = context.async();

        vertx.deployVerticle(ApiVerticle.class.getName(), new DeploymentOptions().setConfig(config), res -> {
            if (res.succeeded()) {
                ProxyHelper.registerService(PersistenceService.class, vertx, new EchoPersistenceService(vertx), PersistenceService.SERVICE_ADDRESS);
                persistenceProxy = ProxyHelper.createProxy(PersistenceService.class, vertx, PersistenceService.SERVICE_ADDRESS);
                persistenceProxy.initialize(context.asyncAssertSuccess());

                asyncStart.complete();
            } else {
                context.fail(res.cause());
            }
        });

        asyncStart.awaitSuccess(5000);
    }

    private HttpServer createOpenIdMockServer(String jwksCerts) {
        return AuthTest.vertx.createHttpServer().requestHandler(request -> {
            HttpServerResponse response = request.response();
            response.putHeader(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
            JsonObject content = new JsonObject();
            content.put("issuer", "https://auth.dave.dbg-devops.com/auth/realms/DAVe");
            content.put("jwks_uri", JWKSAuthProviderImpl.class.getResource(jwksCerts).toString());
            response.end(content.toBuffer());
        });
    }

    private HttpServer createOpenIdMockServerFailing() {
        return AuthTest.vertx.createHttpServer().requestHandler(request -> {
            HttpServerResponse response = request.response();
            response.close();
        });
    }

    private HttpServer createOpenIdMockServerInvalidJwks() {
        return AuthTest.vertx.createHttpServer().requestHandler(request -> {
            HttpServerResponse response = request.response();
            response.putHeader(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
            JsonObject content = new JsonObject();
            content.put("issuer", "https://auth.dave.dbg-devops.com/auth/realms/DAVe");
            content.put("jwks_uri", "invalid");
            response.end(content.toBuffer());
        });
    }

    @Test
    public void testValidJWT(TestContext context) throws URISyntaxException {
        HttpServer openIdMockServer = this.createOpenIdMockServer(CERTS_VALID);
        Async openIdStarted = context.async();
        openIdMockServer.listen(TestConfig.OPENID_PORT, context.asyncAssertSuccess(i -> openIdStarted.complete()));
        openIdStarted.awaitSuccess(5000);
        JsonObject config = TestConfig.getApiConfig();
        config.getJsonObject("auth").put("enable", true);
        deployApiVerticle(context, config);

        createSslRequest("/api/v1.0/pr/latest")
                .putHeader("Authorization", "Bearer " + JWT_TOKEN)
                .send(context.asyncAssertSuccess(res ->
                        context.assertEquals(200, res.statusCode())
                ));
        openIdMockServer.close(context.asyncAssertSuccess());
    }

    @Test
    public void testInvalidPublicKey(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_INVALID), JWT_TOKEN);
    }

    @Test
    public void testFailingOpenId(TestContext context) throws URISyntaxException, InterruptedException {
        this.testFailingServer(context, this.createOpenIdMockServerFailing());
    }

    @Test
    public void testInvalidJwksUrl(TestContext context) throws URISyntaxException, InterruptedException {
        this.testFailingServer(context, this.createOpenIdMockServerInvalidJwks());
    }

    @Test
    public void testExpiredJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), EXPIRED_JWT_TOKEN);
    }

    @Test
    public void testInvalidJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), INVALID_JWT_TOKEN);
    }

    @Test
    public void testInvalidKidJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), INVALID_KID_JWT_TOKEN);
    }

    @Test
    public void testNoKidJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), NO_KID_JWT_TOKEN);
    }

    @Test
    public void testNoJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), "");
    }

    @Test
    public void testInvalidIssuerJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), INVALID_ISSUER_JWT_TOKEN);
    }

    @Test
    public void testInvalidAudienceJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), INVALID_AUD_JWT_TOKEN);
    }

    @Test
    public void testInvalidAudienceArrayJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), INVALID_AUD_ARRAY_JWT_TOKEN);
    }

    @Test
    public void testInvalidAudienceAzpJWT(TestContext context) throws URISyntaxException {
        this.testFailingAuth(context, this.createOpenIdMockServer(CERTS_VALID), INVALID_AUD_AZP_JWT_TOKEN);
    }

    private void testFailingAuth(TestContext context, HttpServer openIdServer, String jwtToken) {
        Async openIdStarted = context.async();
        openIdServer.listen(TestConfig.OPENID_PORT, context.asyncAssertSuccess(i -> openIdStarted.complete()));
        openIdStarted.awaitSuccess(5000);
        JsonObject config = TestConfig.getApiConfig();
        config.getJsonObject("auth").put("enable", true);
        deployApiVerticle(context, config);

        createSslRequest("/api/v1.0/am/latest")
                .putHeader("Authorization", "Bearer " + jwtToken)
                .send(context.asyncAssertSuccess(res ->
                        context.assertEquals(401, res.statusCode())
                ));
        openIdServer.close(context.asyncAssertSuccess());
    }

    private void testFailingServer(TestContext context, HttpServer openIdServer) throws InterruptedException {
        Async openIdStarted = context.async();
        openIdServer.listen(TestConfig.OPENID_PORT, context.asyncAssertSuccess(i -> openIdStarted.complete()));
        openIdStarted.awaitSuccess(5000);
        JsonObject config = TestConfig.getApiConfig();
        config.getJsonObject("auth").put("enable", true);
        Async deployFailed = context.async();
        vertx.deployVerticle(ApiVerticle.class.getName(), new DeploymentOptions().setConfig(config),
                context.asyncAssertFailure(i -> deployFailed.complete()));
        deployFailed.awaitSuccess(5000);
        context.assertFalse(new HealthCheck(vertx).isComponentReady(HealthCheck.Component.API));
        openIdServer.close(context.asyncAssertSuccess());
    }

    @Test
    public void testCSRF(TestContext context) throws InterruptedException, URISyntaxException {
        HttpServer openIdMockServer = this.createOpenIdMockServer(CERTS_VALID);
        Async openIdStarted = context.async();
        openIdMockServer.listen(TestConfig.OPENID_PORT, context.asyncAssertSuccess(i -> openIdStarted.complete()));
        openIdStarted.awaitSuccess(5000);
        JsonObject config = TestConfig.getApiConfig();
        config.getJsonObject("auth").put("enable", true);
        config.getJsonObject("csrf").put("enable", true);
        deployApiVerticle(context, config);

        createSslRequest("/api/v1.0/pr/latest")
                .putHeader("Authorization", "Bearer " + JWT_TOKEN)
                .send(context.asyncAssertSuccess(res -> {
                    context.assertEquals(200, res.statusCode());

                    final String csrfToken = getCsrfCookie(res.cookies())
                            .orElseThrow(() -> new RuntimeException("XSRF-TOKEN cookie not found"));

                    createSslPostRequest("/api/v1.0/pr/delete")
                            .putHeader("Authorization", "Bearer " + JWT_TOKEN)
                            .putHeader("X-XSRF-TOKEN", csrfToken)
                            .send(context.asyncAssertSuccess(csrfRes -> {
                                // We expect "Not found (404)" error code instead of "Forbidden (403)"
                                context.assertEquals(404, csrfRes.statusCode());
                            }));
                }));
        openIdMockServer.close(context.asyncAssertSuccess());
    }

    private Optional<String> getCsrfCookie(List<String> cookies) {
        return cookies.stream()
                .filter(cookie -> cookie.startsWith("XSRF-TOKEN="))
                .map(cookie -> cookie.replaceFirst("XSRF-TOKEN=", "").replaceFirst("; Path=.*", ""))
                .findFirst();
    }

    private HttpRequest<Buffer> createSslRequest(String uri) {
        WebClientOptions sslOpts = new WebClientOptions()
                .setSsl(true)
                .setPemTrustOptions(TestConfig.HTTP_API_CERTIFICATE.trustOptions());

        return WebClient.create(vertx, sslOpts)
                .get(TestConfig.API_PORT, "localhost", uri);
    }

    private HttpRequest<Buffer> createSslPostRequest(String uri) {
        WebClientOptions sslOpts = new WebClientOptions()
                .setSsl(true)
                .setPemTrustOptions(TestConfig.HTTP_API_CERTIFICATE.trustOptions());

        return WebClient.create(vertx, sslOpts)
                .post(TestConfig.API_PORT, "localhost", uri);
    }

    @After
    public void cleanup(TestContext context) {
        vertx.deploymentIDs().forEach(id ->
            vertx.undeploy(id, context.asyncAssertSuccess())
        );
    }

    @AfterClass
    public static void tearDown(TestContext context) {
        vertx.close(context.asyncAssertSuccess());
    }
}
