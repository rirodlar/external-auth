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
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Autenticación externa contra API.
 *
 * Mapea:
 *  - HTTP 200 + success:true => SUCCESS
 *  - HTTP 200 + success:false + message contiene "el usuario no existe" => NO_SUCH_USER
 *  - HTTP 200 + success:false + otro mensaje => BAD_CREDENTIALS
 *  - HTTP != 200 => BAD_CREDENTIALS (con logging)
 */
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
    public int authenticate(Context context, String username, String password, String realm, HttpServletRequest request) {
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

            String basic = Base64.getEncoder()
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
            int status = resp.statusCode();
            String body = resp.body();

            if (status != 200) {
                if (bodyLoggingEnabledOnError()) {
                    log.error("ExternalAuth HTTP={} user={} body={}", status, username, body);
                } else {
                    log.error("ExternalAuth HTTP={} user={} (resumen oculto: body logging desactivado)", status, username);
                }
                return BAD_CREDENTIALS;
            }

            // Esperado: {"success":true|false, "data":{...}, "message":"..."}
            JsonNode root = mapper.readTree(body);
            boolean success = root.has("success") && root.get("success").asBoolean(false);
            String apiMessage = root.hasNonNull("message") ? root.get("message").asText() : null;

            if (!success) {
                String msgLower = apiMessage == null ? "" : apiMessage.toLowerCase(Locale.ROOT);
                boolean isNoSuchUser = containsAny(msgLower, loadNotFoundPatterns());
                if (isNoSuchUser) {
                    log.warn("ExternalAuth FAIL (NO_SUCH_USER) user={} reason='{}'", username, apiMessage);
                    return NO_SUCH_USER;
                } else {
                    log.warn("ExternalAuth FAIL (BAD_CREDENTIALS) user={} reason='{}'", username, apiMessage);
                    return BAD_CREDENTIALS;
                }
            }

            // success=true -> provisión / actualización
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
                        log.warn("ExternalAuth: usuario {} autenticado externamente pero autoprovision desactivada", email);
                        return NO_SUCH_USER;
                    }
                    ep = ePersonService.create(context);
                    // --- setters en EPerson (no en EPersonService) ---
                    ep.setEmail(email);
                    ep.setNetid(apiUserName);
                    ep.setCanLogIn(true);
                } else if (!ep.canLogIn()) {
                    ep.setCanLogIn(true);
                }

                // nombres si vienen en el JSON (tu modelo requiere Context en los setters de nombre)
                if (data.hasNonNull("firstName")) {
                    ep.setFirstName(context, data.get("firstName").asText());
                }
                if (data.hasNonNull("lastName")) {
                    ep.setLastName(context, data.get("lastName").asText());
                }

                ePersonService.update(context, ep);

                // Mapear tipo -> Grupo (opcional)
                if (tipo != null) {
                    Map<String,String> tipoMap = parseTipoToGroupMap(
                            config.getProperty("authentication.external.tipo_to_group", ""));
                    String groupName = tipoMap.get(tipo);
                    if (groupName != null && !groupName.isBlank()) {
                        Group g = groupService.findByName(context, groupName);
                        if (g == null) {
                            g = groupService.create(context);
                            groupService.setName(g, groupName); // firma correcta en tu versión
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
            log.info("ExternalAuth OK user={}", apiUserName);
            return SUCCESS;

        } catch (Exception e) {
            log.error("ExternalAuth exception user={} - {}", username, e.toString());
            return NO_SUCH_USER;
        }
    }

    @Override
    public boolean isImplicit() {
        return false;
    }

    @Override
    public List<Group> getSpecialGroups(Context c, HttpServletRequest r) {
        return Collections.emptyList();
    }

    @Override
    public void initEPerson(Context context, HttpServletRequest request, EPerson eperson) {
        // opcional
    }

    @Override
    public boolean allowSetPassword(Context context, HttpServletRequest request, String username) {
        // No permitimos cambio de contraseña vía DSpace para este método externo
        return false;
    }

    @Override
    public String loginPageURL(Context context, HttpServletRequest request, HttpServletResponse response) {
        return null; // usar la página por defecto
    }

    @Override
    public boolean canSelfRegister(Context context, HttpServletRequest request, String username) {
        // No auto-registro explícito; la creación se controla con autoprovision en local.cfg
        return false;
    }

    @Override
    public String getName() {
        return "external-api";
    }

    @Override
    public boolean isUsed(Context context, HttpServletRequest request) {
        // Siempre activo si está declarado en authentication-external.xml
        return true;
    }

    @Override
    public boolean canChangePassword(Context context, EPerson eperson, String username) {
        // Contraseñas no se gestionan en DSpace para este método
        return false;
    }

    // ========= Helpers =========

    private HttpClient buildHttpClient(boolean insecure, int timeoutMs) throws Exception {
        HttpClient.Builder b = HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofMillis(timeoutMs));
        if (insecure) {
            TrustManager[] trustAll = new TrustManager[] {
                    new X509TrustManager() {
                        // (sin @Override para evitar incompatibilidades de compilador)
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
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
        // formato: tipo1=Grupo A;tipo2=Grupo B|tipo3=Grupo C
        String[] tokens = cfg.split("[;|]");
        for (String t : tokens) {
            String[] kv = t.split("=", 2);
            if (kv.length == 2) {
                String k = kv[0].trim();
                String v = kv[1].trim();
                if (!k.isEmpty() && !v.isEmpty()) {
                    map.put(k, v);
                }
            }
        }
        return map;
    }

    private String resolveEmail(String userOrEmail) {
        if (isEmail(userOrEmail)) return userOrEmail;
        String domain = config.getProperty("authentication.external.default_email_domain", "usach.cl").trim();
        return userOrEmail + "@" + domain;
    }

    private Set<String> loadNotFoundPatterns() {
        // Por defecto usamos "el usuario no existe"
        String raw = config.getProperty("authentication.external.api.message_user_not_found_contains",
                "el usuario no existe");
        return Arrays.stream(raw.split(",|;|\\|"))
                .map(s -> s == null ? "" : s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    private boolean bodyLoggingEnabledOnError() {
        return config.getBooleanProperty("authentication.external.api.log_body_on_error", false);
    }

    private boolean containsAny(String haystackLower, Set<String> needlesLower) {
        for (String n : needlesLower) {
            if (haystackLower.contains(n)) {
                return true;
            }
        }
        return false;
    }

    private String required(String key) {
        String v = config.getProperty(key);
        if (v == null || v.isBlank()) throw new IllegalStateException("Missing config: " + key);
        return v;
    }

    private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static boolean isEmail(String s) {
        return s != null && EMAIL_RX.matcher(s).matches();
    }
}

