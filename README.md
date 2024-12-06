# Security-Toolz
Security

# Herramienta de Seguridad para Bug Hunters

Este proyecto es una herramienta diseñada para profesionales de la ciberseguridad que buscan identificar vulnerabilidades, endpoints de API, tokens y realizar escaneos de puertos. Utiliza diversas técnicas, como la inyección de parámetros y el uso de Shodan API, para ayudar en auditorías de seguridad.

## Funcionalidades Principales

1. **Buscar dispositivos en Shodan**:
   - Realiza búsquedas en Shodan para encontrar dispositivos expuestos.
   - Muestra información relevante sobre hosts, como la dirección IP y la organización.

2. **Obtener Información de Hosts**:
   - Obtén detalles específicos de un host a través de su IP usando la API de Shodan.

3. **Análisis de URLs**:
   - Analiza páginas web para encontrar endpoints de API y tokens Bearer.
   - Detecta respuestas de error comunes (HTTP 400, 404, 500).

4. **Cargar URLs desde un Archivo**:
   - Permite cargar múltiples URLs desde un archivo y analizarlas automáticamente.

5. **Inyección de Payloads**:
   - Permite cargar payloads desde un archivo para realizar inyecciones de prueba en un sitio web.

6. **Escaneo de Puertos**:
   - Escanea puertos abiertos en un objetivo utilizando Nmap.

7. **Verificación de Vulnerabilidades**:
   - Utiliza una API externa para verificar posibles vulnerabilidades en un objetivo.

8. **Ejecutar Nuclei**:
   - Ejecuta el escáner de vulnerabilidades Nuclei sobre un objetivo.

9. **Generación de Reportes**:
   - Guarda los resultados en formato JSON, TXT o XLSX.

## Requisitos

- Python 3.6 o superior
- Bibliotecas necesarias:
  - `requests`
  - `aiohttp`
  - `nmap`
  - `pandas`
  - `colorama`
  - `random_user_agent`
  - `subprocess`
  - `json`

## Instalación

1. **Clona el repositorio**:

   ```bash
   git clone https://github.com/RAXOR84/Extract-Api-Rest-seguridad.git
   cd herramienta-de-seguridad

2.

  pip install -r requirements.txt

3.

  python3 main.py



Uso
Shodan:

Ingresa una consulta o IP para buscar dispositivos expuestos o información de hosts.
Análisis de URLs:

Ingresa una URL para encontrar endpoints de API y tokens Bearer.
Escaneo de Puertos:

Escanea puertos abiertos de un host utilizando Nmap.
Inyección de Payloads:

Carga un archivo con payloads para realizar inyecciones de prueba en URLs.



Crecimiento y Uso Comercial
Este proyecto puede crecer y expandirse en varios frentes:

Patrocinadores y Donaciones: Al ser open source, puede atraer patrocinadores interesados en ciberseguridad mediante donaciones o suscripciones premium que ofrezcan características avanzadas o informes más detallados.

Integración con Otros Servicios: A medida que crece, podría integrarse con más APIs de ciberseguridad, agregar herramientas como scanners de vulnerabilidades adicionales o análisis de malware.

Funcionalidades de Pago: Podría ofrecer un servicio premium para empresas con características como escaneos automáticos programados, reportes personalizados o un dashboard web para visualizar resultados en tiempo real.

Contacto
Si tienes alguna pregunta o quieres contribuir, puedes abrir un issue en GitHub o contactar a [samael_lcf@outlook.com].


