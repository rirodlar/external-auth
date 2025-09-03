# external-authusach (DSpace 7.6.1)

Plugin de autenticación externa para DSpace-CRIS 7.6.1. Valida credenciales contra `https://cuentas.segic.cl/api/cuenta/check`.


## Descripción General
Este plugin implementa un sistema de autenticación para DSpace que valida las credenciales de usuario contra una API externa mediante llamadas REST. 
Permite sincronizar información de usuario entre el sistema externo y DSpace, manteniendo un único punto de gestión de credenciales.
Ejemplo de respuesta del API:




### Características Principales
- Autenticación de usuarios contra una API externa REST
- Aprovisionamiento automático de usuarios en DSpace 
- Sincronización de datos de usuario desde el sistema externo 
- Asignación automática a grupos DSpace según el tipo de usuario 
- Soporte para conexiones seguras e inseguras (desarrollo)


### Requisitos Técnicos
DSpace 7.x (compatible con 7.6.1)
Java 11
Maven para compilación

## Configuración
El plugin utiliza las siguientes propiedades de configuración en dspace.cfg:

```md
# URL de la API externa para autenticación
authentication.external.api.url = https://cuentas.segic.cl/api/cuenta/check

# Credenciales para la API externa
authentication.external.api.username = dspace_client
authentication.external.api.password = secret_password

# Timeouts y configuración de seguridad
authentication.external.api.timeout = 5000
authentication.external.api.insecure_tls = false

# Aprovisionamiento automático de usuarios
authentication.external.autoprovision = true

# Dominio para generar emails automáticamente
authentication.external.email_fallback_domain = usach.cl

# Mapeo de tipos de usuario a grupos DSpace
authentication.external.tipo_to_group = ACADEMICO=Académicos,ESTUDIANTE=Estudiantes

```

## Formato de Respuesta de la API

```json
{"success":true,"data":{"user":"felipe.fuentesb","password":"<hash>","tipo":"ACADEMICO","rut":"167406386"}}
```

## Instalación

Compile el plugin con Maven: mvn clean package
Copie el JAR generado a la carpeta [dspace]/lib/
Configure las propiedades en dspace.cfg
Añada com.usach.dspace.ExternalApiAuthentication a la propiedad plugin.sequence.org.dspace.authenticate.AuthenticationMethod
Reinicie DSpace

## Seguridad
- Utiliza autenticación básica para la API externa 
- Soporta conexiones TLS 
- Opción para desarrollo con TLS inseguro (no recomendado para producción)
- Las contraseñas son gestionadas por el sistema externo

## Resumen del flujo (end-to-end)

1. UI/REST: DSpace recibe POST /server/api/authn/login con email y password.

2. AuthenticationService llama a los AuthenticationMethod registrados en orden. 
3. ExternalApiAuthentication:
    - Lee email/password. 
    - Hace HTTP POST a https://cuentas.segic.cl/api/cuenta/check (con timeouts y headers). 
    - Si la respuesta es “válida”, retorna SUCCESS y opcionalmente autoregistra el EPerson si no existe (si decides permitirlo). 
    - Si es inválida, retorna BAD_CREDENTIAL y DSpace sigue con el siguiente método (p.ej. Password) o falla.

4. DSpace emite token y completa el login.

## URL
```
# --- External Auth (SEGIC) ---
external.auth.enabled = true
external.auth.endpoint = https://cuentas.segic.cl/api/cuenta/check
external.auth.timeout.ms = 3000
external.auth.connect.timeout.ms = 1000
external.auth.read.timeout.ms = 2000

# Si el API exige header Authorization / API-Key, etc.
external.auth.auth-header = Authorization
external.auth.auth-value = Bearer XXXXXX

# Autocreación de EPerson si login externo pasa pero el usuario no existe
external.auth.auto-create-eperson = true
external.auth.email-domain-fallback = usach.cl
```
