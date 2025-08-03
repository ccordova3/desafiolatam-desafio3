import socket
import subprocess
import whois
from decouple import config
from tqdm import tqdm
import warnings

# Cargar el objetivo y los puertos desde el archivo .env
target = config('RECON_TARGET')
portsFromEnvStr = config('RECON_PORTS', default=None)
customPorts = None
if portsFromEnvStr:
    try:
        customPorts = [int(p.strip()) for p in portsFromEnvStr.split(',')]
    except ValueError:
        print("ADVERTENCIA: La variable RECON_PORTS en .env contiene valores no numéricos. Se usarán los puertos por defecto.")
        customPorts = None

class ReconScanner:
    """
    Clase para realizar un escaneo de reconocimiento de superficie de ataque.
    Incluye Whois para dominios, Ping para verificar actividad y un escaneo de puertos limitado.
    """
    def __init__(self, targetHost: str, portsToScan: list = None):
        self.targetHost = targetHost
        
        self.isIp = False
        try:
            socket.inet_aton(self.targetHost)
            self.isIp = True
        except socket.error:
            pass
            
        if portsToScan is None:
            self.portsToScan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443]
        else:
            self.portsToScan = sorted([int(p) for p in portsToScan])

    def performWhoisLookup(self):
        """
        Realiza una consulta Whois para obtener información de registro de un dominio.
        """
        print(f"\n--- Realizando consulta Whois para: {self.targetHost} ---")
        try:
            whoisData = whois.whois(self.targetHost)
            if whoisData.domain_name:
                print(f"  > Dominio: {whoisData.domain_name}")
                print(f"  > Registrador: {whoisData.registrar}")
                print(f"  > Organización: {whoisData.org}")
                print(f"  > Fechas de creación: {whoisData.creation_date}")
                print(f"  > Servidores DNS: {whoisData.name_servers}")
            else:
                print(f"  > No se encontraron resultados Whois para {self.targetHost}.")
        except Exception as e:
            print(f"  > Error en la consulta Whois: {e}")

    def performPingTest(self):
        """
        Realiza un ping para verificar si un host está activo.
        """
        print(f"\n--- Verificando estado del host con Ping para: {self.targetHost} ---")
        try:
            command = ['ping', '-c', '1', self.targetHost]
            response = subprocess.run(command, capture_output=True, text=True, timeout=5)
            
            if response.returncode == 0:
                print(f"  > El host {self.targetHost} está activo.")
            else:
                print(f"  > El host {self.targetHost} no responde al ping.")
        except FileNotFoundError:
            print("  > Error: El comando 'ping' no se encontró. Asegúrate de que está en tu PATH.")
        except subprocess.TimeoutExpired:
            print(f"  > Timeout: El host {self.targetHost} no respondió a tiempo.")
        except Exception as e:
            print(f"  > Error al ejecutar ping: {e}")

    def performPortScan(self):
        """
        Realiza un escaneo de puertos limitado para detectar servicios.
        """
        print(f"\n--- Iniciando escaneo de puertos en {self.targetHost} ---")
        openPorts = []
        
        with tqdm(total=len(self.portsToScan), desc="Escaneando puertos", unit="puertos", ncols=80) as pbar:
            for port in self.portsToScan:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((self.targetHost, port))
                    if result == 0:
                        openPorts.append(port)
                    sock.close()
                except socket.gaierror:
                    print("\n  > Error: No se pudo resolver el nombre del host. Verifica la IP o dominio.")
                    return
                except Exception as e:
                    pass
                pbar.update(1)

        if openPorts:
            print(f"\n  > Puertos abiertos encontrados: {sorted(openPorts)}")
        else:
            print("\n  > No se encontraron puertos abiertos en el rango especificado.")

    def runScan(self):
        """
        Orquesta la ejecución de todas las técnicas de reconocimiento.
        """
        if not self.isIp:
            self.performWhoisLookup()
        
        self.performPingTest()
        self.performPortScan()

def main():
    warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
    
    print("=== Herramienta de Reconocimiento de Superficie de Ataque (Requerimiento 1) ===")
    print("El objetivo se carga desde la variable 'RECON_TARGET' en tu archivo .env.")

    # Usar la lista de puertos del .env si está disponible
    portsToScan = customPorts if customPorts else [21, 22, 23, 25, 53, 80, 110, 135, 139, 443]

    scanner = ReconScanner(target, portsToScan)
    scanner.runScan()
    
    print("\n--- Reconocimiento de superficie de ataque completado ---")

if __name__ == "__main__":
    main()