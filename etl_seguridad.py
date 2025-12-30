import requests
import pandas as pd
from sqlalchemy import create_engine
from datetime import datetime
import time

# --- ⚙️ CONFIGURACIÓN ---
# Reemplaza 'tu_password' por la contraseña que pusiste al instalar PostgreSQL
USUARIO_DB = 'postgres'
PASSWORD_DB = 'TU_CONTRASEÑA_AQUI'
HOST_DB = 'localhost'
PORT_DB = '5432'
NOMBRE_DB = 'seguridad_iot'

# Palabras clave de seguridad electrónica a monitorear
KEYWORDS = ['Hikvision', 'Dahua', 'ZKTeco', 'Uniview', 'DVR', 'NVR']

# Conexión a la Base de Datos (PostgreSQL)
CADENA_CONEXION = f'postgresql+psycopg2://{USUARIO_DB}:{PASSWORD_DB}@{HOST_DB}:{PORT_DB}/{NOMBRE_DB}'
engine = create_engine(CADENA_CONEXION)

def obtener_cves(keyword):
    """ EXTRAER: Consulta la API del NIST buscando vulnerabilidades por marca """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': keyword}
    
    print(f"🔎 Buscando amenazas para: {keyword}...")
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"⚠️ Error {response.status_code} al consultar API.")
            return None
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return None

def procesar_datos(json_data, keyword):
    """ TRANSFORMAR: Limpia el JSON y lo convierte en una tabla ordenada """
    lista_cves = []
    
    vulnerabilidades = json_data.get('vulnerabilities', [])
    
    for item in vulnerabilidades:
        cve = item['cve']
        
        # Intentamos obtener la severidad (a veces es v3, a veces v2, a veces nula)
        try:
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                severidad = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV2' in metrics:
                score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                severidad = metrics['cvssMetricV2'][0]['baseSeverity']
            else:
                score = 0.0
                severidad = "DESCONOCIDA"
        except:
            score = 0.0
            severidad = "ERROR"

        fila = {
            'cve_id': cve['id'],
            'marca_detectada': keyword,
            'descripcion': cve['descriptions'][0]['value'],
            'fecha_publicacion': cve['published'][:10], # Solo fecha YYYY-MM-DD
            'severidad': severidad,
            'score': score,
            'fecha_carga': datetime.now().strftime('%Y-%m-%d')
        }
        lista_cves.append(fila)
        
    return pd.DataFrame(lista_cves)

def cargar_a_postgres(df):
    """ CARGAR: Guarda en SQL evitando duplicados """
    if df.empty:
        return
    
    # 1. Leemos qué IDs ya existen en la base de datos para no repetirlos
    try:
        query_existentes = "SELECT cve_id FROM vulnerabilidades"
        ids_existentes = pd.read_sql(query_existentes, engine)['cve_id'].tolist()
    except:
        ids_existentes = [] # Si la tabla no existe aún, la lista es vacía

    # 2. Filtramos: Dejamos solo los que NO están en la base de datos
    df_nuevos = df[~df['cve_id'].isin(ids_existentes)]
    
    # 3. Guardamos solo los nuevos
    if not df_nuevos.empty:
        df_nuevos.to_sql('vulnerabilidades', engine, if_exists='append', index=False)
        print(f"✅ ¡Guardadas {len(df_nuevos)} nuevas vulnerabilidades en PostgreSQL!")
    else:
        print("💤 No hay amenazas nuevas (ya estaban todas registradas).")

def main():
    print("--- 🛡️ INICIANDO ESCANEO DE SEGURIDAD IOT ---")
    
    total_encontradas = 0
    
    for key in KEYWORDS:
        json_data = obtener_cves(key)
        
        if json_data:
            df = procesar_datos(json_data, key)
            print(f"   -> Encontrados {len(df)} registros brutos.")
            cargar_a_postgres(df)
            total_encontradas += len(df)
        
        # Respetamos al servidor del NIST esperando un poco entre peticiones
        time.sleep(2)

    print("\n--- 🏁 PROCESO TERMINADO ---")

if __name__ == '__main__':
    main()