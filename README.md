# Atención ciudadana PQRS

Sistema gratuito y de código abierto para que una entidad pública reciba, gestione y responda peticiones, quejas, reclamos y sugerencias (PQRS).

No tiene dependencias externas: solo necesita **Node.js 22.13 o superior**. La base de datos (SQLite) viene incluida en Node.

## Qué hace

**Ciudadano** (página principal)
- Radica una solicitud con asunto, descripción, datos de contacto opcionales y hasta 3 adjuntos (PDF, PNG, JPG, DOCX, XLSX; 5 MB cada uno).
- Recibe un radicado consecutivo (`PQRS-2026-000001`) y una clave de 6 caracteres.
- Consulta el estado, la respuesta y el historial con el radicado y la clave.
- Ve la fecha límite de respuesta, calculada en días hábiles.

**Funcionarios** (`/gestion`)
- Ingreso con correo y contraseña. Dos roles: administrador y funcionario.
- Bandeja con contadores (sin tomar, por vencer, vencidas), búsqueda y filtros.
- Cambiar estado, reasignar dependencia, asignar a una persona, responder y dejar notas internas que el ciudadano no ve.
- Descargar adjuntos y exportar la bandeja a CSV (se abre bien en Excel).
- El administrador crea usuarios, define el nombre de la entidad y las dependencias.
- Un funcionario con dependencia solo ve las solicitudes de su dependencia y las que le asignen.

**Plazos.** Se cuentan en días hábiles, sin sábados, domingos ni festivos de Colombia (calculados automáticamente con la Ley Emiliani, para cualquier año). Los plazos por defecto son 15 días (peticiones, quejas, reclamos, sugerencias), 10 (información y documentos) y 30 (consultas), según la Ley 1755 de 2015. Si su entidad usa otros, cámbielos en `server.js`, constante `TIPOS`.

## Probarlo en su computador (2 minutos)

1. Instale Node.js 22 o superior desde https://nodejs.org
2. Abra una terminal en esta carpeta y ejecute:

```
node server.js
```

3. La primera vez se crea el administrador y se muestra su contraseña en la terminal. Cópiela.
4. Abra http://localhost:3000 (ciudadanos) y http://localhost:3000/gestion (funcionarios).

Para elegir usted el correo y la contraseña del administrador:

```
ADMIN_EMAIL=admin@su-entidad.gov.co ADMIN_PASSWORD=una-clave-larga node server.js
```

(En Windows PowerShell: `$env:ADMIN_EMAIL="..."; $env:ADMIN_PASSWORD="..."; node server.js`)

Los datos se guardan en la carpeta `data/`.

## Publicarlo para que los ciudadanos lo usen

El sistema guarda todo en archivos (base de datos y adjuntos), así que necesita un servidor con **disco que no se borre**. Eso descarta muchos servicios gratuitos de "hosting para aplicaciones", que reinician el disco en cada despliegue o cuando la aplicación se duerme y harían perder las solicitudes. Verifique siempre las condiciones vigentes del proveedor antes de decidir.

Opciones realistas:

1. **Un servidor de la propia entidad** (recomendado si existe): cualquier equipo con Node.js 22 o Docker, con HTTPS delante.
2. **Una máquina virtual gratuita permanente** de un proveedor de nube que ofrezca ese nivel (por ejemplo, el nivel "Always Free" de Oracle Cloud; confirme que sigue vigente en su región). Es gratis, pero requiere un par de horas de configuración.
3. **Un servidor pequeño de pago** (suele costar pocos dólares al mes) si prefiere no administrar nada complejo.

### Instalación en un servidor Linux con Docker

```
git clone <su copia del proyecto>   # o copie la carpeta con scp
cd atencion-ciudadana-pqrs
cp .env.example .env
nano .env                           # defina ADMIN_EMAIL y ADMIN_PASSWORD
docker compose up -d --build
```

Queda escuchando en `127.0.0.1:3000`. Falta ponerle HTTPS. La forma más simple es Caddy (obtiene el certificado solo). Con un dominio apuntando al servidor, un `Caddyfile` así basta:

```
pqrs.su-entidad.gov.co {
    reverse_proxy 127.0.0.1:3000
}
```

En `.env` deje `TRUST_PROXY=1`. Sin HTTPS no publique el sistema: las contraseñas viajarían sin cifrar.

### Instalación sin Docker

```
node server.js
```

Para que arranque solo y se reinicie, use un servicio de systemd:

```
[Unit]
Description=Atencion ciudadana PQRS
After=network.target

[Service]
WorkingDirectory=/opt/atencion-ciudadana-pqrs
Environment=PORT=3000 TRUST_PROXY=1
EnvironmentFile=/opt/atencion-ciudadana-pqrs/.env
ExecStart=/usr/bin/node server.js
Restart=always
User=pqrs

[Install]
WantedBy=multi-user.target
```

## Respaldos

Haga copias periódicas. Es la parte más importante de operar este sistema.

```
node scripts/respaldo.js /ruta/del/respaldo
```

Genera una copia consistente de la base de datos y de los adjuntos, aunque el sistema esté en uso. Con Docker: `docker compose exec pqrs node scripts/respaldo.js /app/data/respaldos/hoy` y luego copie esa carpeta fuera del servidor. Programe el comando con `cron` (por ejemplo, cada noche) y guarde copias en otro lugar.

## Variables de entorno

| Variable | Para qué sirve |
|---|---|
| `PORT` | Puerto del servidor (3000 por defecto). |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Primer administrador. Solo se usan si la base de datos está vacía. |
| `TRUST_PROXY` | Poner `1` detrás de un proxy con HTTPS. |
| `TZ_ENTIDAD` | Zona horaria para los días hábiles (`America/Bogota`). |
| `DATA_DIR` | Carpeta de la base de datos y los adjuntos (`./data`). |

## Seguridad: lo que ya incluye

- Contraseñas y claves de radicado guardadas con hash (scrypt), nunca en texto plano.
- Sesiones con cookie `HttpOnly`, `SameSite` y `Secure` bajo HTTPS; caducan a las 8 horas.
- Protección contra CSRF, límites de intentos de ingreso, consulta y radicación, y cabeceras de seguridad (CSP, anti-clickjacking).
- Los adjuntos se validan por extensión y por contenido, se guardan con nombre aleatorio y se descargan solo con sesión iniciada.
- La consulta ciudadana nunca muestra el nombre ni el contacto del solicitante, ni las notas internas.

## Lo que debe resolver la entidad

- **Política de tratamiento de datos** (Ley 1581 de 2012) y aviso de privacidad. El formulario trae una frase de autorización; revísela con su área jurídica.
- **Notificación por correo.** El sistema no envía correos. El ciudadano consulta con su radicado y clave; si deja un contacto, el funcionario puede escribirle por fuera del sistema.
- **Plazos y términos.** Confirme que los plazos por tipo coinciden con la norma y los procedimientos internos de su entidad.
- **Un solo servidor.** Está pensado para entidades pequeñas y medianas con una instancia. Para alta disponibilidad habría que migrar a una base de datos de red.
- Cambie la contraseña del administrador al primer ingreso (menú "Mi cuenta") y use contraseñas de al menos 10 caracteres.

## Prueba automática

Con el sistema en marcha y una base de datos vacía:

```
ADMIN_EMAIL=... ADMIN_PASSWORD=... BASE=http://localhost:3000 node scripts/prueba.js
```

Recorre el flujo completo: radicar, consultar, ingresar, asignar, responder, permisos por dependencia, adjuntos, exportación y administración. Crea solicitudes de prueba, así que no la ejecute sobre datos reales.

## Estructura

```
server.js        servidor y API
lib/             base de datos, utilidades HTTP, fechas y festivos
public/          pantallas (ciudadano y funcionarios)
scripts/         prueba automática y respaldo
Dockerfile, docker-compose.yml, .env.example
```

Licencia MIT: puede usarlo, modificarlo y compartirlo libremente.
