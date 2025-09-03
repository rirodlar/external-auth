package com.usach.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.*;
import java.util.regex.Pattern;

public class ExternalApiAuthentication implements AuthenticationMethod {

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
        if (isBlank(username) || isBlank(password)) {
            return BAD_ARGS;
        }

        try {
            boolean insecure = config.getBooleanProperty("authentication.external.api.insecure_tls", false);
            int timeoutMs = config.getIntProperty("authentication.external.api.timeout", 5000);
            HttpClient client = buildHttpClient(insecure, timeoutMs);

            String apiUrl  = required("authentication.external.api.url");
            String apiUser = required("authentication.external.api.username");
            String apiPass = required("authentication.external.api.password");

            String basic = java.util.Base64.getEncoder()
                    .encodeToString((apiUser + ":" + apiPass).getBytes(StandardCharsets.UTF_8));
            String payload = "{\"user\":\"" + escape(username) + "\",\"password\":\"" + escape(password) + "\"}";

            HttpRequest httpReq = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .timeout(java.time.Duration.ofMillis(timeoutMs))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Basic " + basic)
                    .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> resp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());
            boolean accept200 = config.getBooleanProperty("authentication.external.api.accept_http200_as_valid", false);
            if (resp.statusCode() != 200) {
                return BAD_CREDENTIALS;
            }

            // {"success":true,"data":{"user":"...","tipo":"...","rut":"..."}}
            JsonNode root = mapper.readTree(resp.body());
            boolean success = root.has("success") && root.get("success").asBoolean(false);
            if (!success && !accept200) {
                return BAD_CREDENTIALS;
            }
            JsonNode data = root.has("data") ? root.get("data") : mapper.createObjectNode();
            String apiUserName = data.hasNonNull("user") ? data.get("user").asText() : username;
            String tipo = data.hasNonNull("tipo") ? data.get("tipo").asText() : null;

            String email = resolveEmail(apiUserName);
            EPerson ep = ePersonService.findByEmail(context, email);

            context.turnOffAuthorisationSystem();
            try {
                if (ep == null) {
                    boolean autoProvision = config.getBooleanProperty("authentication.external.autoprovision", true);
                    if (!autoProvision) {
                        return NO_SUCH_USER;
                    }
                    ep = ePersonService.create(context);
                    ep.setEmail(email);              // setters simples
                    ep.setNetid(apiUserName);
                    ep.setCanLogIn(true);
                } else if (!ep.canLogIn()) {
                    ep.setCanLogIn(true);
                }

                // nombres si vienen en el JSON
                if (data.hasNonNull("firstName")) {
                    ep.setFirstName(context, data.get("firstName").asText());
                }
                if (data.hasNonNull("lastName")) {
                    ep.setLastName(context, data.get("lastName").asText());
                }

                ePersonService.update(context, ep);

                // === Mapear tipo -> Grupo (opcional) ===
                if (tipo != null) {
                    Map<String,String> tipoMap = parseTipoToGroupMap(
                            config.getProperty("authentication.external.tipo_to_group", ""));
                    String groupName = tipoMap.get(tipo);
                    if (groupName != null && !groupName.isBlank()) {
                        Group g = groupService.findByName(context, groupName);
                        if (g == null) {
                            g = groupService.create(context);
                            groupService.setName(g, groupName);
                            groupService.update(context, g);
                        }
                        if (!groupService.isMember(context, ep, g)) {
                            groupService.addMember(context, g, ep);
                            groupService.update(context, g);
                        }
                    }
                }
            } finally {
                context.restoreAuthSystemState();
            }

            context.setCurrentUser(ep);
            return SUCCESS;

        } catch (Exception e) {
            return NO_SUCH_USER;
        }
    }

    // ===== Métodos requeridos por AuthenticationMethod =====

    @Override
    public boolean canSelfRegister(Context c, HttpServletRequest r, String u) throws SQLException {
        return config.getBooleanProperty("authentication.external.autoprovision", true);
    }

    @Override
    public boolean allowSetPassword(Context c, HttpServletRequest r, String u) throws SQLException {
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
        return username.toLowerCase() + "@" + domain;
    }

    private HttpClient buildHttpClient(boolean insecure, int timeoutMs) throws Exception {
        HttpClient.Builder b = HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofMillis(timeoutMs));
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
        return map;
    }

    private String required(String key) {
        String v = config.getProperty(key);
        if (v == null || v.isBlank()) throw new IllegalStateException("Missing config: " + key);
        return v;
    }

    private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }
    private static String escape(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }
    private static boolean isEmail(String s) { return s != null && EMAIL_RX.matcher(s).matches(); }
}
