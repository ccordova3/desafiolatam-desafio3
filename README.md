# Desafío: Suite de Hacking Ético Automatizada con Python

**Advertencia: Esta herramienta es solo para fines educativos y de prueba en entornos de laboratorio controlados. El uso de estas técnicas sin la debida autorización es ilegal y no ético.**

Este proyecto es una suite de herramientas de hacking ético automatizadas, desarrolladas en Python, para simular las fases de un test de penetración. La suite incluye scripts para el reconocimiento de superficie de ataque, la enumeración de servicios y la explotación controlada de vulnerabilidades web comunes.

El objetivo es demostrar la capacidad de automatizar tareas de ciberseguridad, siguiendo metodologías profesionales y aplicando los conceptos aprendidos sobre programación, redes y seguridad web.

## Estructura del Proyecto

El proyecto está organizado en cuatro scripts principales, uno para cada requerimiento del desafío y un orquestador principal:

* `recon_scanner.py`: Script para la fase de reconocimiento.
* `service_enumerator.py`: Script para la fase de enumeración de servicios.
* `web_vuln_scanner.py`: Script para la fase de explotación de vulnerabilidades web.
* `main_pentest_suite.py`: Script principal que orquesta la ejecución de los tres scripts en secuencia.

Además, el proyecto utiliza un archivo `.env` para centralizar toda la configuración, lo que hace que la herramienta sea más flexible y reutilizable.

## Requerimientos y Funcionalidades

### Requerimiento 1: Script de Reconocimiento
Este script realiza un reconocimiento de superficie de ataque utilizando técnicas activas y pasivas:
* **Consulta Whois**: Para obtener información de registro de un dominio.
* **Ping Test**: Para verificar si un host está activo.
* **Escaneo de Puertos**: Realiza un escaneo de puertos limitado para identificar servicios comunes.

### Requerimiento 2: Sistema de Enumeración de Servicios Modulares
Este script se enfoca en la fase de enumeración y utiliza una arquitectura modular para:
* **Escaneo de Puertos Multihilo**: Identifica puertos abiertos de manera eficiente.
* **Detección de Banners**: Captura banners para identificar la versión de los servicios.
* **Enumeración Avanzada**: Incluye módulos específicos para FTP (login anónimo), SSH (versión de banner) y HTTP (encabezados, título de página).

### Requerimiento 3: Herramientas de Explotación Web
Este script está diseñado para la detección controlada de vulnerabilidades web y cuenta con las siguientes funcionalidades. Las pruebas están orientadas a una aplicación vulnerable como **DVWA (Damn Vulnerable Web Application)**, que se ejecuta en una máquina virtual como **Metasploitable2**.
* **Detección de SQL Injection**: Prueba inyecciones basadas en errores de base de datos y retardos de tiempo.
* **Detección de XSS Reflected**: Inyecta payloads de XSS y busca su reflejo en la respuesta HTML.
* **Detección de XSS Stored**: Simula un ataque persistente, inyectando un payload y verificando su persistencia en la página web.

## Configuración y Uso

### 1. Requisitos
Asegúrate de tener Python 3.x y `pip` instalados. Es altamente recomendado utilizar un entorno virtual para este proyecto. **La ejecución de estos scripts requiere un entorno de laboratorio controlado, siendo Metasploitable2 con la aplicación DVWA la herramienta de testeo principal.**

### 2. Archivo de Configuración (`.env`)
Antes de ejecutar los scripts, debes configurar el archivo `.env` con las variables de tu entorno de laboratorio. A continuación se muestra un ejemplo con todos los valores parametrizables. **Recuerda ajustar las direcciones IP y URLs a tu entorno de Metasploitable2.**

```ini
# Configuración para Reconocimiento (Requerimiento 1)
RECON_TARGET="desafiolatam.com"
RECON_PORTS="21,22,23,25,53,80,110,135,139,443"

# Configuración para Enumeración (Requerimiento 2)
ENUM_TARGET_IP="192.168.100.102"
ENUM_PORTS="21,22,23,25,53,80,110,139,443,445,3389,8080"

# Configuración para Explotación Web (Requerimiento 3)
WEB_VULN_TARGET="http://192.168.100.102/dvwa"
WEB_LOGIN_USERNAME="admin"
WEB_LOGIN_PASSWORD="password"
SQLI_GET_PARAMS="id,Submit"
SQLI_POST_PARAMS="username,password"
XSS_REFLECTED_GET_PARAMS="name,Submit"
XSS_REFLECTED_POST_PARAMS="comment,name,Submit"
XSS_STORED_SUBMIT_PARAMS="name,message,Submit"
```

### 3. Instalación de Dependencias
Con tu entorno virtual activado, instala las librerías necesarias con el siguiente comando:

```ini
pip install python-decouple tqdm python-whois requests beautifulsoup4 lxml
```
### 4. Ejecución
Puedes ejecutar la suite completa o cada script de forma individual, dependiendo de tus necesidades.

#### Ejecutar la Suite Completa (Recomendado)
Para ejecutar todas las fases del test de penetración de forma secuencial, utiliza el siguiente comando. Los resultados completos se guardarán en un archivo results-<timestamp>.txt en la misma carpeta.

```ini
python3 main_pentest_suite.py
```

#### Ejecutar Scripts Individuales
Si deseas ejecutar cada script por separado para centrarte en una fase específica, utiliza los siguientes comandos:

##### Fase 1: Reconocimiento:

```ini
python3 recon_scanner.py
```

##### Fase 2: Enumeración:

```ini
python3 service_enumerator.py
```

##### Fase 3: Explotación:

```ini
python3 web_vuln_scanner.py
````