# communication-service — VetChain

Servicio de mensajería interna. Habilita la conversación **usuario ↔ administración** mediante
conversaciones, mensajes y un canal en tiempo real (SSE).

## Responsabilidad en la arquitectura

Es el **canal de comunicación** de la plataforma (desde 2.10). Permite que los usuarios operativos
planteen dudas o incidencias a su administrador y que este responda, con estados de lectura y
notificaciones en vivo.

- Gestiona conversaciones (una por usuario) y mensajes.
- Expone un flujo **SSE** (`/stream`) para recibir mensajes sin recargar.
- Marca mensajes como leídos y calcula no leídos.

## Tecnologías

| Componente | Versión |
|---|---|
| Node.js | ≥ 18 |
| Express | ^5.2.1 |
| pg | ^8.16.3 |
| amqplib (RabbitMQ) | ^0.10.9 |
| dotenv | ^18.0.1 |
| SSE | nativo (Server-Sent Events) |

## Instalación y ejecución

**Método oficial (recomendado): Docker Compose**, desde la raíz del proyecto:

```bash
docker compose up -d --build --wait
```

**Ejecución directa** (requiere PostgreSQL y RabbitMQ):

```bash
npm install
node index.js        # o: npm start
```

El servicio escucha en `PORT` (3010 por defecto).

## Endpoints principales

| Método | Ruta | Rol | Descripción |
|---|---|---|---|
| GET | `/` , `/health` | Público | Identificación y estado. |
| GET | `/stream` | Autenticado | Flujo SSE de mensajes en vivo. |
| GET | `/conversations/me` | Usuario | Mi conversación. |
| POST | `/conversations/me/messages` | Usuario | Envía un mensaje. |
| POST | `/conversations/me/read` | Usuario | Marca mi conversación como leída. |
| GET | `/conversations` | admin / master-admin | Listado de conversaciones (con ámbito). |
| GET | `/conversations/:id/messages` | Autenticado | Mensajes de una conversación. |
| POST | `/conversations/:id/messages` | Autenticado | Responde en una conversación. |
| POST | `/conversations/:id/read` | Autenticado | Marca una conversación como leída. |
| PATCH | `/conversations/:id` | admin / master-admin | Actualiza el estado de una conversación. |
| GET | `/unread` | Autenticado | Contador de no leídos. |

El prefijo del Gateway es `/chat` (`/chat/conversations/me`, `/chat/stream`, …).

## Variables de entorno

| Variable | Defecto | Descripción |
|---|---|---|
| `PORT` | `3010` | Puerto de escucha. |
| `DATABASE_URL` | — | Conexión a PostgreSQL. |
| `DB_NAME` | — | Base de datos a usar dentro de la misma instancia. |
| `DB_POOL_MAX` | `10` | Tamaño máximo del pool. |
| `RABBITMQ_URL` | `amqp://localhost:5672` | Conexión AMQP. |
| `JWT_SECRET` | — | Verificación del token. |
| `AUTH_SERVICE_URL` | `http://localhost:3001` | Validación de sesión/ámbito. |

## Base de datos

- `conversations` — una conversación por usuario (estado, marca de lectura).
- `messages` — mensajes de cada conversación (autor, cuerpo, fecha, leído).

## Reglas de negocio

- El **ámbito** se respeta: un `admin` solo ve las conversaciones de sus propios usuarios; un
  `master-admin`, todas.
- La mensajería está disponible para los dueños de conversación (`CHAT_OWNERS`) y la administración.
- El canal SSE (`/stream`) mantiene la conexión abierta y empuja los mensajes nuevos.

## Eventos

- No consume ni publica eventos de negocio en RabbitMQ; la entrega en vivo es vía SSE.

## Notas de despliegue

En Render, este servicio se despliega en la región **Ohio** como
`vetchain26-communication`.
