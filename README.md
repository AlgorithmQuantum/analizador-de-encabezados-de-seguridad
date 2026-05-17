# analizador-de-encabezados-de-seguridad
Herramienta web para análisis automatizado de cabeceras de seguridad HTTP. Identifica vulnerabilidades de configuración (XSS, clickjacking, MITM) y genera reportes con puntuación de riesgo por cabecera. Probada contra 20+ sitios reales.
# Analizador de Cabeceras de Seguridad

Una aplicación web en Flask para auditar cabeceras HTTP de seguridad y evaluar la configuración de un sitio. El proyecto analiza encabezados como `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy` y `Permissions-Policy`, y presenta un reporte con puntuación de riesgo y recomendaciones.

## Características

- Interfaz web ligera con análisis inmediato.
- Soporta análisis desde la página principal y una API JSON (`/api/analyze`).
- Evalúa la presencia y el valor de cabeceras clave de seguridad.
- Genera una puntuación global de seguridad y clasifica el riesgo en bajo, medio o alto.
- Muestra recomendaciones claras por cada cabecera.
- Incluye estilos visuales mediante `static/style.css`.

## Estructura del proyecto

- `app.py` - aplicación Flask principal.
- `utils/header_checker.py` - lógica de análisis de cabeceras de seguridad.
- `templates/index.html` - formulario de entrada y página principal.
- `templates/resultados.html` - página de resultados del análisis.
- `static/style.css` - estilos CSS de la aplicación.
- `requirements.txt` - dependencias del proyecto.

## Requisitos

- Python 3.11+ (recomendado)
- `pip`

## Instalación

1. Clona el repositorio:

```bash
git clone https://github.com/AlgorithmQuantum/analizador-de-encabezados-de-seguridad.git
cd analizador-de-encabezados-de-seguridad
```

2. Crea y activa un entorno virtual:

```bash
python -m venv venv
venv\Scripts\activate
```

3. Instala las dependencias:

```bash
pip install -r requirements.txt
```

## Uso

1. Inicia la aplicación Flask:

```bash
python app.py
```

2. Abre tu navegador en:

```text
http://127.0.0.1:5000
```

3. Ingresa una URL para analizar sus cabeceras de seguridad.

## API REST

Puedes usar la API JSON para integrar el análisis en otras herramientas.

- Endpoint: `POST /api/analyze`
- Payload JSON:

```json
{ "url": "https://ejemplo.com" }
```

- Respuesta de ejemplo:

```json
{
  "url": "https://ejemplo.com",
  "status_code": 200,
  "final_url": "https://ejemplo.com",
  "headers_analyzed": [ ... ],
  "summary": { ... },
  "overall_risk": "Medio 🟡"
}
```

## Cómo funciona

La clase `SecurityHeaderChecker` en `utils/header_checker.py` realiza lo siguiente:

- Normaliza la URL para usar `https://` si no se proporciona protocolo.
- Realiza una petición HTTP con `requests`.
- Verifica cada cabecera contra reglas definidas en `HEADER_RULES`.
- Calcula puntajes de riesgo y clasifica el resultado.
- Devuelve un objeto con detalles de cabeceras, estado y recomendaciones.

## Contribuciones

Si deseas mejorar el proyecto, puedes:

- Agregar más cabeceras de seguridad para analizar.
- Mejorar el análisis de valores y la lógica de puntuación.
- Añadir pruebas unitarias.
- Mejorar la interfaz de usuario.

## Licencia

Este proyecto está publicado bajo la licencia `MIT`.
