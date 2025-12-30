# Tracker de vulnerabilidades equipos
**Sistema ETL para monitoreo proactivo de ciberseguridad en dispositivos IoT y Seguridad Electrónica.**

Este proyecto nació de la necesidad de auditar masivamente el estado de seguridad de hardware crítico (Cámaras IP, DVRs, Controles de Acceso). Automatiza la consulta a bases de datos gubernamentales (NIST NVD) para detectar vulnerabilidades (CVEs) antes de que sean explotadas.

##  Funcionalidades
* **Extracción Automática:** Consulta la API del NIST buscando marcas específicas (Hikvision, Dahua, ZKTeco, etc.).
* **Filtrado Inteligente:** Identifica y clasifica amenazas por severidad (CRITICAL, HIGH).
* **Almacenamiento Persistente:** Guarda el historial en **PostgreSQL** evitando duplicados.
* **Análisis de Riesgo:** Permite visualizar qué marcas presentan mayor exposición a fallos de seguridad.

##  Tecnologías Utilizadas
* **Lenguaje:** Python 3.9+
* **Base de Datos:** PostgreSQL 17
* **Librerías Clave:**
    * `Pandas`: Limpieza y transformación de datos JSON.
    * `SQLAlchemy`: ORM para conexión eficiente a SQL.
    * `Requests`: Comunicación con API REST.

##  Impacto del Negocio
Permite a los Gerentes de Seguridad pasar de una "reacción ante incidentes" a una "prevención basada en datos", identificando qué equipos necesitan parches de firmware urgentes.

---
*Desarrollado por Félix Lezama - 2025*
