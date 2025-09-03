#!/usr/bin/env bash
set -euo pipefail

# === CONFIG LOCAL ===
JAR_LOCAL_PATH="target/external-auth-1.0.1.jar"   # cámbialo si tu jar está en otra ruta
SERVER_IP="187.33.149.132"
SERVER_USER="root"

# === RUTAS REMOTAS ===
LIB_DIR="/var/lib/tomcat9/webapps/server/WEB-INF/lib"
DSPACE_CFG_DIR="/var/lib/dspace/config"
SPRING_API_DIR="$DSPACE_CFG_DIR/spring/api"
AUTH_XML="$SPRING_API_DIR/authentication-external.xml"
LOCALE_CFG="$DSPACE_CFG_DIR/local.cfg"
LOGBACK="$DSPACE_CFG_DIR/logback.xml"

echo ">> Verificando JAR local: $JAR_LOCAL_PATH"
test -f "$JAR_LOCAL_PATH" || { echo "No existe $JAR_LOCAL_PATH"; exit 1; }

echo ">> Subiendo JAR a /tmp del servidor ($SERVER_USER@$SERVER_IP)"
scp "$JAR_LOCAL_PATH" "$SERVER_USER@$SERVER_IP:/tmp/external-auth-1.0.1.jar"

echo ">> Ejecutando tareas remotas (mover JAR, crear XML, setear config y reiniciar Tomcat)"
ssh -tt "$SERVER_USER@$SERVER_IP" bash -lc "'
  set -euo pipefail

  echo \">> Creando directorios si faltan\"
  mkdir -p \"$LIB_DIR\" \"$SPRING_API_DIR\"

  echo \">> Moviendo JAR al classpath de la app\"
  mv /tmp/external-auth-1.0.1.jar \"$LIB_DIR/external-auth-1.0.1.jar\"
  chmod 644 \"$LIB_DIR/external-auth-1.0.1.jar\"

  echo \">> Escribiendo override de Spring: $AUTH_XML\"
  cat > \"$AUTH_XML\" <<\"XML\"
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<beans xmlns=\"http://www.springframework.org/schema/beans\"
       xmlns:util=\"http://www.springframework.org/schema/util\"
       xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
       xsi:schemaLocation=\"
        http://www.springframework.org/schema/beans     http://www.springframework.org/schema/beans/spring-beans.xsd
        http://www.springframework.org/schema/util      http://www.springframework.org/schema/util/spring-util.xsd\">

    <bean id=\"cl.usach.auth.ExternalApiAuthentication\"
          class=\"cl.usach.auth.ExternalApiAuthentication\">
        <property name=\"enabled\" value=\"\${external.auth.enabled}\"/>
        <property name=\"endpoint\" value=\"\${external.auth.endpoint}\"/>
        <property name=\"connectTimeoutMs\" value=\"\${external.auth.connect.timeout.ms}\"/>
        <property name=\"readTimeoutMs\" value=\"\${external.auth.read.timeout.ms}\"/>
        <property name=\"authHeader\" value=\"\${external.auth.auth-header}\"/>
        <property name=\"authValue\" value=\"\${external.auth.auth-value}\"/>
        <property name=\"autoCreateEPerson\" value=\"\${external.auth.auto-create-eperson}\"/>
        <property name=\"emailDomainFallback\" value=\"\${external.auth.email-domain-fallback}\"/>
    </bean>

    <util:list id=\"plugin.sequence.org.dspace.authenticate.AuthenticationMethod\">
        <ref bean=\"cl.usach.auth.ExternalApiAuthentication\"/>
        <ref bean=\"org.dspace.authenticate.PasswordAuthentication\"/>
    </util:list>
</beans>
XML

  echo \">> Asegurando claves en local.cfg\"
  grep -q \"external.auth.endpoint\" \"$LOCALE_CFG\" || cat >> \"$LOCALE_CFG\" <<'CFG'

# --- External Auth (SEGIC) ---
external.auth.enabled = true
external.auth.endpoint = https://cuentas.segic.cl/api/cuenta/check
external.auth.connect.timeout.ms = 1000
external.auth.read.timeout.ms = 2000
external.auth.auth-header = Authorization
external.auth.auth-value = Bearer XXXXXX
external.auth.auto-create-eperson = true
external.auth.email-domain-fallback = usach.cl
CFG

  echo \">> Activando logger del plugin (si no existe)\"
  if ! grep -q 'logger name=\"cl.usach.auth\"' \"$LOGBACK\"; then
    sed -i \"s#</configuration>#  <logger name=\\\"cl.usach.auth\\\" level=\\\"DEBUG\\\"/>\\n</configuration>#\" \"$LOGBACK\"
  fi

  echo \">> Reiniciando Tomcat\"
  systemctl restart tomcat9
  sleep 5
  systemctl is-active --quiet tomcat9 && echo \"Tomcat activo\" || (echo \"Tomcat no activo\"; journalctl -u tomcat9 -n 200 --no-pager; exit 1)

  echo \">> Buscando logs de tu autenticador\"
  journalctl -u tomcat9 -n 400 --no-pager | grep -i \"ExternalApiAuthentication\\|cl.usach.auth\" || true
'"

echo ">> Hecho. Ahora prueba el login REST:"
echo "curl -i -X POST \"https://sic.vriic.usach.cl/server/api/authn/login\" -H \"Content-Type: application/json\" --data '{\"email\":\"usuario@usach.cl\",\"password\":\"secreto\"}'"

