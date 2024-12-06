import os
import re
import requests
import aiohttp
import asyncio
import subprocess
from random_user_agent.user_agent import UserAgent
import json
import pandas as pd
from datetime import datetime
from colorama import Fore, Style, init
import nmap  # Asegúrate de tener nmap instalado.


# Inicializa el colorama
init(autoreset=True)


class ApiEndpointFinder:
    def __init__(self):
        self.patron_api = r'https?://[^\s]+(?:/[^/\s]+)+'
        self.patron_token = r'(?i)Bearer ([\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}|[A-Za-z0-9-_]+(?:\.[A-Za-z0-9-_]+){2})'
        self.codigos_permitidos = {200, 400, 401, 403, 404, 500, 302}
        self.user_agent_generator = UserAgent()

    def get_random_user_agent(self):
        return self.user_agent_generator.get_random_user_agent()

    def encontrar_api_endpoints(self, texto):
        return list(set(re.findall(self.patron_api, texto)))

    def encontrar_bearer_tokens(self, texto):
        return list(set(re.findall(self.patron_token, texto)))

    async def analizar_url(self, url):
        headers = {'User-Agent': self.get_random_user_agent()}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status in self.codigos_permitidos:
                        texto = await response.text()
                        endpoints = self.encontrar_api_endpoints(texto)
                        tokens = self.encontrar_bearer_tokens(texto)
                        return endpoints, tokens
                    else:
                        print(f"El código de estado {response.status} no está permitido para análisis.")
                        return [], []
        except aiohttp.ClientError as e:
            print(f"Error al realizar la solicitud a {url}: {e}")
            return [], []

    def ejecutar_inyeccion(self, url, payload):
        try:
            response = requests.get(url, params={'inject': payload})
            return response.status_code, response.text
        except requests.RequestException as e:
            print(f"Error al realizar la inyección en {url}: {e}")
            return None, None


class ShodanClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
        self.user_agent_generator = UserAgent()

    def get_random_user_agent(self):
        return self.user_agent_generator.get_random_user_agent()

    async def _make_request(self, url):
        headers = {'User-Agent': self.get_random_user_agent()}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientConnectorError as e:
                print(f"Error de conexión: {e}")
                return None
            except Exception as e:
                print(f"Error inesperado: {e}")
                return None

    async def search(self, query):
        url = f"{self.base_url}/shodan/host/search?key={self.api_key}&query={query}"
        return await self._make_request(url)

    async def host_info(self, ip):
        url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"
        return await self._make_request(url)


class PortScanner:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def scan_ports(self):
        print(f"Escaneando puertos para {self.target}...")
        try:
            self.scanner.scan(self.target, '1-1024')
            open_ports = []
            for proto in self.scanner[self.target].all_protocols():
                for port in self.scanner[self.target][proto].keys():
                    if self.scanner[self.target][proto][port]['state'] == 'open':
                        open_ports.append(port)
            return open_ports
        except Exception as e:
            print(f"Ocurrió un error al escanear puertos: {e}")
            return []


class VulnerabilityScanner:
    def __init__(self, api_endpoint):
        self.vulnerability_api = api_endpoint

    def check_vulnerabilities(self, ip):
        try:
            response = requests.get(f"{self.vulnerability_api}/check/{ip}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as err:
            print(f"HTTP error occurred: {err}")
            return None
        except Exception as e:
            print(f"Error al verificar vulnerabilidades: {e}")
            return None

    def run_nuclei(self, target):
        try:
            command = ["nuclei", "-u", target, "-o", "resultados_nuclei.txt"]
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode == 0:
                print(Fore.GREEN + Style.BRIGHT + "Escaneo de Nuclei completado. Resultados guardados en 'resultados_nuclei.txt'.")
            else:
                print(Fore.RED + Style.BRIGHT + f"Error al ejecutar Nuclei: {result.stderr}")

        except Exception as r:
            print(Fore.RED + Style.BRIGHT + f"Ocurrió un error al ejecutar Nuclei: {r}")


def guardar_resultados(resultados, nombre_archivo='resultados', formato='json'):
    carpeta_reportes = 'Reportes'
    if not os.path.exists(carpeta_reportes):
        os.makedirs(carpeta_reportes)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    ruta_archivo = os.path.join(carpeta_reportes, f"{nombre_archivo}_{timestamp}.{formato}")

    try:
        if formato == 'json':
            with open(ruta_archivo, 'w') as archivo:
                json.dump(resultados, archivo, indent=4)
            print(f"Resultados guardados en JSON: {ruta_archivo}")
        elif formato == 'txt':
            with open(ruta_archivo, 'w') as archivo:
                archivo.write(f"{resultados}")
            print(f"Resultados guardados en TXT: {ruta_archivo}")
        elif formato == 'xlsx':
            df = pd.DataFrame(resultados)
            df.to_excel(ruta_archivo, index=False)
            print(f"Resultados guardados en XLSX: {ruta_archivo}")
        else:
            print("Formato no soportado.")
    except Exception as e:
        print(f"Error al guardar resultados: {e}")


def mostrar_resultados(endpoints_encontrados, tokens_encontrados):
    print("\nResultados:")
    if endpoints_encontrados:
        print("Endpoints encontrados:")
        for endpoint in endpoints_encontrados:
            print(f" - {endpoint}")
    else:
        print(Fore.RED + "No se encontraron endpoints.")

    if tokens_encontrados:
        print("\nTokens Bearer encontrados:")
        for token in tokens_encontrados:
            print(f" - {token}")
    else:
        print(Fore.YELLOW + "No se encontraron tokens Bearer.")


async def cargar_urls_desde_archivo(archivo, api_finder):
    try:
        with open(archivo, 'r') as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()  
                if url:  
                    print(f"\nAnalizando URL: {url}")
                    endpoints_encontrados, tokens_encontrados = await api_finder.analizar_url(url)
                    mostrar_resultados(endpoints_encontrados, tokens_encontrados)
    except FileNotFoundError:
        print("Error: El archivo no fue encontrado.")


async def cargar_payloads_desde_archivo(archivo_payloads, api_finder):
    try:
        with open(archivo_payloads, 'r') as file:
            payloads = file.readlines()
            url = input("Ingrese la URL para ejecutar los payloads: ")
            for payload in payloads:
                payload = payload.strip()  
                if payload:  
                    status_code, respuesta = api_finder.ejecutar_inyeccion(url, payload)
                    generar_reporte(payload, status_code, respuesta)
    except FileNotFoundError:
        print("Error: El archivo no fue encontrado.")


def generar_reporte(payload, status_code, respuesta):
    if status_code is not None:
        with open('reporte_inyecciones.txt', 'a') as report_file:
            report_file.write(f"Payload: {payload}\nCódigo de estado: {status_code}\nRespuesta:\n{respuesta}\n\n")
        print(f"Inyección ejecutada con éxito. Código de estado: {status_code}.\nRespuesta guardada en 'reporte_inyecciones.txt'.")
        print(f"\nPayload: {payload}")
        print(f"Status Code: {status_code}")
        print(f"Respuesta: {respuesta}")
    else:
        print("No se pudo ejecutar la inyección.")


async def main():
    api_key = os.getenv("SHODAN_API_KEY")
    vulnerability_api_endpoint = "https://cloud.projectdiscovery.io/"
  
    if not api_key:
        print("Error: La API Key no está configurada en las variables de entorno.")
        return

    shodan_client = ShodanClient(api_key)
    api_finder = ApiEndpointFinder()
    vulnerability_scanner = VulnerabilityScanner(vulnerability_api_endpoint)

    while True:
        print(Fore.GREEN + "\nMenú:")
        print("1. Buscar dispositivos por consulta")
        print("2. Obtener información sobre un host específico")
        print("3. Analizar una URL para encontrar endpoints y tokens")
        print("3. Cargar URLs desde un archivo")
        print("4. Cargar payloads desde un archivo")
        print("5. Escanear puertos abiertos")
        print("6. Verificar vulnerabilidades")
        print("7. Ejecutar Nuclei")
        print("8. Salir")

        opcion = input("Seleccione una opción (1-8): ")

        if opcion == '1':
            query = input("Ingrese la consulta de búsqueda: ").strip()
            resultados = await shodan_client.search(query)
            if resultados and 'matches' in resultados:
                print(f"\nResultados para '{query}':")
                for match in resultados['matches']:
                    print(f" - IP: {match['ip_str']}, Organización: {match.get('org', 'N/A')}")
                formato = input("¿Desea guardar los resultados? (si/no): ").strip().lower()
                if formato == 'si':
                    tipo_guardado = input("¿En qué formato desea guardar los resultados? (json/txt/xlsx): ").strip().lower()
                    guardar_resultados(resultados['matches'], 'resultados_busqueda', tipo_guardado)
            else:
                print("No se encontraron resultados.")

        elif opcion == '2':
            ip = input("Ingrese la dirección IP del host: ").strip()
            info_host = await shodan_client.host_info(ip)
            if info_host:
                print(f"\nInformación para '{ip}':")
                for key, value in info_host.items():
                    print(f"{key}: {value}")
                formato = input("¿Desea guardar los resultados? (si/no): ").strip().lower()
                if formato == 'si':
                    tipo_guardado = input("¿En qué formato desea guardar los resultados? (json/txt/xlsx): ").strip().lower()
                    guardar_resultados(info_host, 'info_host', tipo_guardado)
            else:
                print("No se encontró información para este host.")

        elif opcion == '3':
            url = input("Ingrese la URL a analizar: ").strip()
            endpoints, tokens = await api_finder.analizar_url(url)
            mostrar_resultados(endpoints, tokens)

        elif opcion == '4':
            archivo = input("Ingrese la ruta del archivo con URLs: ")
            await cargar_urls_desde_archivo(archivo, api_finder)

        elif opcion == '5':
            ip = input("Ingrese la IP a escanear: ").strip()
            port_scanner = PortScanner(ip)
            open_ports = port_scanner.scan_ports()
            if open_ports:
                print(Fore.GREEN + f"Puertos abiertos en {ip}: {', '.join(map(str, open_ports))}")
                guardar_resultados(open_ports, 'puertos_abiertos', 'json')
            else:
                print(Fore.RED + f"No se encontraron puertos abiertos en {ip}.")

        elif opcion == '6':
            ip = input("Ingrese la IP para verificar vulnerabilidades: ").strip()
            vulnerabilities = vulnerability_scanner.check_vulnerabilities(ip)
            if vulnerabilities:
                print(f"Vulnerabilidades encontradas para {ip}: {json.dumps(vulnerabilities, indent=4)}")
                guardar_resultados(vulnerabilities, 'vulnerabilidades', 'json')
            else:
                print(Fore.YELLOW + f"No se encontraron vulnerabilidades para {ip} o no se pudo verificar.")

        elif opcion == '7':
            ip = input("Ingrese la IP para ejecutar Nuclei: ").strip()
            vulnerability_scanner.run_nuclei(ip)

        elif opcion == '8':
            print("Saliendo del programa.")
            break
        else:
            print("Opción no válida. Intente de nuevo.")


if __name__ == "__main__":
    asyncio.run(main())
