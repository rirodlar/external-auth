#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TOMCAT_LIB="/var/lib/tomcat9/webapps/server/WEB-INF/lib"
JAR_NAME="external-auth-1.0.1.jar"

echo ">>> Compilando..."
mvn -q -f "$PROJECT_DIR/pom.xml" clean package -DskipTests

echo ">>> Copiando JAR a Tomcat..."
sudo cp "$PROJECT_DIR/target/$JAR_NAME" "$TOMCAT_LIB/"

echo ">>> Reiniciando Tomcat..."
sudo systemctl restart tomcat9

echo "OK. Revisa: sudo journalctl -u tomcat9 -f"

