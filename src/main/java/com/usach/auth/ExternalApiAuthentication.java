package com.usach.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.eperson.factory.EPersonServiceFactory;
import org.dspace.eperson.service.EPersonService;
import org.dspace.eperson.service.GroupService;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

public class ExternalApiAuthentication implements AuthenticationMethod {

    private static final Logger log = LogManager.getLogger(ExternalApiAuthentication.class);

    private final ConfigurationService config =
            DSpaceServicesFactory.getInstance().getConfigurationService();
    private final EPersonService ePersonService =
            EPersonServiceFactory.getInstance().getEPersonService();
    private final GroupService groupService =
            EPersonServiceFactory.getInstance().getGroupService();
    private final ObjectMapper mapper = new ObjectMapper();

    private static final Pattern EMAIL_RX =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);

    @Override
    public int authenticate(Context context, String username, String password, String realm, HttpServletRequest request)
            throws SQLException {

        final String reqId = UUID.randomUUID().toString(); // para correlación simple
        final Instant t0 = Instant.now();

        if (isBlank(username) || isBlank(password)) {
            log.warn("[{}] BAD_ARGS: username/password en blanco. username='{}'", reqId, safeUser(username));
            return BAD_ARGS;
        }

        log.debug("[{}] Inicio authenticate: username='{}', realm='{}', remoteAddr='{}'",
                reqId, safeUser(username), realm, remoteAddr(request));

        try {
            boolean insecure = config.getBooleanProperty("authentication.external.api.insecure_tls", false);
            int timeoutMs = config.getIntProperty("authentication.external.api.timeout", 5000);
            boolean accept200 = config.getBooleanProperty("authentication.external.api.accept_http200_as_valid", false);

            String apiUrl  = required("authentication.external.api.url");
            String apiUser = required("authentication.external.api.username");
            String apiPass = required("authentication.external.api.password"); // NO loggear valor

            log.debug("[{}] Config: insecureTLS={}, timeoutMs={}, accept200={}, apiUrl='{}', apiUser='{}'", reqId, insecure, timeoutMs, accept200, apiUrl, mask(apiUser));

            HttpClient client = buildHttpClient(insecure, timeoutMs);

            String basic = java.util.Base64.getEncoder()
                    .encodeToString((apiUser + ":" + apiPass).getBytes(StandardCharsets.UTF_8));
            String payload = "{\"user\":\"" + escape(username) + "\",\"password\":\"" + escape(password) + "\"}";

            HttpRequest httpReq = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .timeout(Duration.ofMillis(timeoutMs))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Basic " + basic) // <-- CORRECTO: se envía el token real
                    .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                    .build();

            log.debug("[{}] HTTP -> POST {} (timeout={}ms). Body: user='{}', password='[REDACTED]'", reqId, apiUrl, timeoutMs, safeUser(username));

            // Llamado HTTP
            Instant tHttp0 = Instant.now();
            HttpResponse<String> resp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());
            Duration dHttp = Duration.between(tHttp0, Instant.now());

            log.debug("[{}] HTTP <- status={} ({} ms). RespBody.len={}",
                    reqId, resp.statusCode(), dHttp.toMillis(),
                    (resp.body() == null ? 0 : resp.body().length()));

            if (resp.statusCode() != 200) {
                log.info("[{}] BAD_CREDENTIALS: status HTTP={} distinto de 200", reqId, resp.statusCode());
                return BAD_CREDENTIALS;
            }

            // Parse JSON
            JsonNode root;
            try {
                root = mapper.readTree(resp.body());
            } catch (Exception parseEx) {
                log.warn("[{}] BAD_CREDENTIALS: no se pudo parsear JSON de respuesta. Error={}",
                        reqId, parseEx.toString());
                return BAD_CREDENTIALS;
            }

            boolean success = root.has("success") && root.get("success").asBoolean(false);
            if (!success && !accept200) {
                log.info("[{}] BAD_CREDENTIALS: success=false y accept200=false", reqId);
                return BAD_CREDENTIALS;
            }

            JsonNode data = root.has("data") ? root.get("data") : mapper.createObjectNode();
            String apiUserName = data.hasNonNull("user") ? data.get("user").asText() : username;
            String tipo = data.hasNonNull("tipo") ? data.get("tipo").asText() : null;

            String email = resolveEmail(apiUserName);
            log.debug("[{}] Usuario API resuelto: apiUserName='{}', email='{}', tipo='{}'", reqId, safeUser(apiUserName), email, tipo);
            EPerson ep = ePersonService.findByEmail(context, email);

            context.turnOffAuthorisationSystem();
            try {
                if (ep == null) {
                    boolean autoProvision = config.getBooleanProperty("authentication.external.autoprovision", true);
                    if (!autoProvision) {
                        log.info("[{}] NO_SUCH_USER: autoprovision=false y usuario no existe '{}'", reqId, email);
                        return NO_SUCH_USER;
                    }
                    ep = ePersonService.create(context);
                    ep.setEmail(email);
                    ep.setNetid(apiUserName);
                    ep.setCanLogIn(true);
                    log.info("[{}] EPerson creado: email='{}', netid='{}'", reqId, email, safeUser(apiUserName));
                } else if (!ep.canLogIn()) {
                    ep.setCanLogIn(true);
                    log.info("[{}] EPerson re-habilitado para login: email='{}'", reqId, email);
                }

                // nombres si vienen en el JSON
                if (data.hasNonNull("firstName")) {
                    ep.setFirstName(context, data.get("firstName").asText());
                    log.debug("[{}] firstName seteado para '{}'", reqId, email);
                }
                if (data.hasNonNull("lastName")) {
                    ep.setLastName(context, data.get("lastName").asText());
                    log.debug("[{}] lastName seteado para '{}'", reqId, email);
                }

                ePersonService.update(context, ep);

                // === Mapear tipo -> Grupo (opcional) ===
                if (tipo != null) {
                    Map<String,String> tipoMap = parseTipoToGroupMap(
                            config.getProperty("authentication.external.tipo_to_group", ""));
                    String groupName = tipoMap.get(tipo);
                    log.debug("[{}] tipo='{}' -> groupName='{}'", reqId, tipo, groupName);

                    if (groupName != null && !groupName.isBlank()) {
                        Group g = groupService.findByName(context, groupName);
                        if (g == null) {
                            g = groupService.create(context);
                            groupService.setName(g, groupName);
                            groupService.update(context, g);
                            log.info("[{}] Grupo creado: '{}'", reqId, groupName);
                        }
                        if (!groupService.isMember(context, ep, g)) {
                            groupService.addMember(context, g, ep);
                            groupService.update(context, g);
                            log.info("[{}] EPerson agregado a grupo: user='{}' -> group='{}'",
                                    reqId, email, groupName);
                        } else {
                            log.debug("[{}] EPerson ya era miembro de grupo '{}'", reqId, groupName);
                        }
                    }
                }
            } finally {
                context.restoreAuthSystemState();
            }

            context.setCurrentUser(ep);
            log.info("[{}] SUCCESS: autenticación OK para '{}'. Total={} ms",
                    reqId, email, Duration.between(t0, Instant.now()).toMillis());
            return SUCCESS;

        } catch (IllegalStateException cfgEx) {
            log.error("[{}] NO_SUCH_USER por configuración faltante: {}", reqId, cfgEx.getMessage());
            return NO_SUCH_USER;
        } catch (Exception e) {
            log.error("[{}] NO_SUCH_USER por excepción inesperada: {}", reqId, e.toString(), e);
            return NO_SUCH_USER;
        }
    }

    // ===== Métodos requeridos por AuthenticationMethod =====

    @Override
    public boolean canSelfRegister(Context c, HttpServletRequest r, String u) throws SQLException {
        boolean v = config.getBooleanProperty("authentication.external.autoprovision", true);
        log.debug("canSelfRegister? {}", v);
        return v;
    }

    @Override
    public boolean allowSetPassword(Context c, HttpServletRequest r, String u) throws SQLException {
        log.debug("allowSetPassword? false");
        return false;
    }

    @Override
    public boolean isImplicit() {
        return false;
    }

    @Override
    public java.util.List<Group> getSpecialGroups(Context c, HttpServletRequest r) throws SQLException {
        return java.util.Collections.emptyList();
    }

    @Override
    public void initEPerson(Context context, HttpServletRequest request, EPerson eperson) throws SQLException {
        // Inicialización opcional post-auth
    }

    @Override
    public String loginPageURL(Context context, HttpServletRequest request, HttpServletResponse response) {
        return null;
    }

    @Override
    public String getName() {
        return "external-api";
    }

    @Override
    public boolean isUsed(Context context, HttpServletRequest request) {
        return true;
    }

    @Override
    public boolean canChangePassword(Context context, EPerson ePerson, String currentPassword) {
        return false;
    }

    // ===== Helpers =====

    private String resolveEmail(String username) {
        if (isEmail(username)) return username.toLowerCase();
        String domain = config.getProperty("authentication.external.email_fallback_domain", "usach.cl");
        String email = username.toLowerCase() + "@" + domain;
        log.debug("resolveEmail: '{}' -> '{}'", safeUser(username), email);
        return email;
    }

    private HttpClient buildHttpClient(boolean insecure, int timeoutMs) throws Exception {
        HttpClient.Builder b = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMs));
        if (insecure) {
            TrustManager[] trustAll = new TrustManager[] {
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] xcs, String s) {}
                        public void checkServerTrusted(X509Certificate[] xcs, String s) {}
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new SecureRandom());
            b.sslContext(sc)
                    .sslParameters(new SSLParameters() {{ setEndpointIdentificationAlgorithm(null); }});
            log.warn("TLS INSEGURO ACTIVADO (solo pruebas).");
        }
        return b.build();
    }

    private Map<String,String> parseTipoToGroupMap(String cfg) {
        Map<String,String> map = new HashMap<>();
        if (cfg == null || cfg.isBlank()) return map;
        for (String pair : cfg.split(",")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) map.put(kv[0].trim(), kv[1].trim());
        }
        log.debug("tipo_to_group mapeado: {}", map);
        return map;
    }

    private String required(String key) {
        String v = config.getProperty(key);
        if (v == null || v.isBlank()) throw new IllegalStateException("Missing config: " + key);
        return v;
    }

    // Helpers de sanitización/log
    private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }
    private static String escape(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }
    private static boolean isEmail(String s) { return s != null && EMAIL_RX.matcher(s).matches(); }
    private static String safeUser(String s) { return (s == null) ? null : s.replaceAll("(?<=.).(?=.*@)|(?<=.).(?=.$)", "*"); }
    private static String mask(String s) { return (s == null || s.length() < 3) ? "***" : s.charAt(0) + "***" + s.charAt(s.length()-1); }
    private static String remoteAddr(HttpServletRequest r) {
        if (r == null) return "n/a";
        String xfwd = r.getHeader("X-Forwarded-For");
        return (xfwd != null && !xfwd.isBlank()) ? xfwd.split(",")[0].trim() : r.getRemoteAddr();
    }
}
