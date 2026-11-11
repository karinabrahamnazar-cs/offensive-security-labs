# SQLi-database-version

### [PortSwigger] SQL injection attack, querying the database type and version on MySQL and Microsoft
**Módulo/Dificultad:** SQL injection | Practitioner  
**Herramienta principal:** Burp Suite (Repeater)  
**Tiempo invertido:** ~10-15 minutos  
**CWE / Vulnerabilidad:** CWE-89 (SQL Injection - UNION Based Database Version Enumeration)  

#### 1. Vector y Punto de Entrada
* **Endpoint afectado:** `GET /filter?category=Gifts`
* **Parámetro vulnerable:** `category`
* **Mecanismo del fallo:** Concatenación directa de la entrada del usuario en la consulta SQL subyacente sin parametrizar ni sanitizar. La aplicación utiliza MySQL o Microsoft SQL Server en el backend, por lo que las sintaxis de comentario de línea y concatenación se ajustan a dialectos que soportan `#` o `-- ` (con espacio) y operadores de consulta específicos.

#### 2. Flujo de explotación
1. **Determinar el número de columnas y tipos compatibles con texto:**
   * Se evalúa el número de columnas enviando valores `NULL`:
     `' UNION SELECT NULL, NULL#` (o `' UNION SELECT NULL, NULL-- `).
   * Se verifica que ambas columnas acepten tipos de texto (`VARCHAR`):
     `' UNION SELECT 'a', 'b'#` (Devuelve HTTP 200 y refleja ambas cadenas en la página HTML).

2. **Identificar motor y versión (MySQL / MS-SQL):**
   * Consultando el *cheat sheet* de PortSwigger para MySQL y Microsoft SQL Server, la variable global que almacena la versión de la base de datos es `@@version`.
   * En MySQL, la sintaxis de comentarios requiere un carácter de espacio después del doble guión (`-- `) o el uso del carácter hash (`#`).

3. **Explotación y extracción:**
   * Inyección del payload para obtener la cadena de versión de la base de datos en una de las columnas reflejadas:
     `' UNION SELECT @@version, NULL#`

4. **Autenticación / Verificación:**
   * La respuesta HTTP 200 proyecta directamente en el cuerpo HTML la versión del motor de base de datos, marcando el laboratorio como completado.

#### 3. Payload clave (PoC final)
```http
GET /filter?category='+UNION+SELECT+@@version,+NULL%23 HTTP/1.1
