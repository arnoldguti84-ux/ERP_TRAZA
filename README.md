# TRAZA — Sistema de gestión de flota

Prototipo funcional de un ERP de gestión de flota vehicular (>50 unidades),
construido como una aplicación web de una sola página (HTML/CSS/JS puro,
sin build step) conectada a Supabase como backend.

## Estado actual

Funciona de punta a punta contra un proyecto de Supabase (cloud o self-hosted):
login, roles, y CRUD real sobre todas las tablas. No es un mockup — los datos
persisten en Postgres.

## Archivos

- `traza-erp.html` — la aplicación completa (frontend + lógica). Un solo archivo,
  sin dependencias de build. Usa `supabase-js` v2 y `SheetJS` (xlsx) vía CDN.
- `schema.sql` — esquema de base de datos para Supabase. Crea todo dentro de un
  schema aislado llamado `traza` (no `public`), para poder convivir con otras
  tablas que ya existan en el mismo proyecto.
- `SETUP.md` — guía paso a paso para conectar la app a un proyecto de Supabase
  ya existente (exponer el schema `traza`, obtener URL/anon key, crear el primer
  usuario admin, publicar la función `create-user`).
- `create-user-function.ts` — Supabase Edge Function que permite al Admin crear
  usuarios desde la app sin exponer la Service Role Key en el navegador. Se
  publica una sola vez (ver SETUP.md 5.1).

## Arquitectura

- **Frontend**: JS vanilla, sin framework. Un objeto `state` global, funciones
  `render*()` por módulo que regeneran el HTML del contenido, y un pequeño
  sistema de modales genérico (`openModal`/`closeModal`).
- **Backend**: Supabase (Postgres + Auth + Data API). Todas las tablas viven en
  el schema `traza`. El cliente se inicializa con `db: { schema: 'traza' }`.
- **Autenticación**: Supabase Auth (email/password). No hay registro público —
  el registro de usuarios ("Allow new users to sign up") está desactivado en
  el proyecto. Los usuarios se crean de dos formas: (1) directamente desde el
  dashboard de Supabase (Authentication > Users > Add user), necesario para el
  primer admin; o (2) desde el módulo Usuarios de la app, que llama a la Edge
  Function `create-user` — esta usa la Service Role Key del lado del servidor
  (nunca en el navegador) y verifica que quien llama ya sea admin antes de
  crear la cuenta. Un trigger en `auth.users` crea automáticamente una fila en
  `traza.profiles` con rol `solo_lectura` apenas se crea la cuenta, por
  cualquiera de los dos caminos.
- **Autorización (roles)**: 3 roles — `admin`, `operaciones`, `solo_lectura` —
  aplicados en dos capas:
  - **RLS en Postgres** (la capa real de seguridad): políticas en cada tabla
    permiten `select` a cualquier usuario autenticado, pero `insert/update/delete`
    solo si `traza.can_write()` es verdadero (admin u operaciones). La tabla
    `profiles` solo la puede modificar `traza.is_admin()`.
  - **UI condicional en el frontend** (solo cosmético/UX): los botones de crear/editar
    se ocultan si el rol es `solo_lectura`, y el módulo "Usuarios" solo se
    muestra si el rol es `admin`. Esto no reemplaza el RLS, es solo para no
    mostrar acciones que el backend rechazaría de todos modos.

## Módulos implementados

Dashboard, Vehículos y documentación (ficha técnica extendida: identificación,
especificaciones, dimensiones/pesos, operación y documentos — con catálogos
administrables para los campos de lista, y carga masiva desde Excel con
plantilla descargable), Mantenimiento, Conductores y
asignaciones, Rutas, Checklist de pre-uso, Neumáticos, Combustible (vale,
fecha/hora, placa, KM, ruta, piloto/copiloto, galones, PPG, ciudad y
proveedor — Costo, Km Recorridos y KPG se calculan siempre al vuelo desde
una vista de Supabase, `traza.fuel_logs_computed`, con el método
"full-to-full"; no hay valores guardados que puedan desactualizarse ni
botón de recálculo), Compras e
inventario, Costos, Reportes (con exportación a Excel y PDF), Usuarios,
Catálogos (gestión de listas desplegables, solo Admin).

## Nota técnica: Km Recorridos y KPG en Combustible

Estos dos valores **no se guardan** como columnas fijas — se calculan cada
vez que se consulta la vista `traza.fuel_logs_computed` (definida en
`schema.sql`), usando ventanas de SQL (window functions) para encontrar,
para cada tanqueo marcado "Full", el Full anterior más cercano de la misma
placa y sumar los galones correspondientes. La app lee de esta vista para
mostrar los datos; el guardado (alta/edición/borrado) sigue siendo sobre la
tabla `traza.fuel_logs`. Este enfoque reemplazó una versión anterior que
calculaba y guardaba estos valores desde el navegador con un botón
"Recalcular", la cual resultó frágil ante cargas fuera de orden, duplicados
y actualizaciones parciales.

## Posibles próximos pasos (a definir con quien continúe el proyecto)

- Migrar de un solo archivo HTML a un proyecto con build (Vite + React o similar)
  si el código sigue creciendo — hoy es manejable pero ya es un archivo grande.
- Agregar tests para la lógica de reportes y de permisos.
- Integración real de GPS/telemetría en el módulo de Rutas (hoy es solo
  programación y estado, sin rastreo en vivo).
- Notificaciones automáticas (correo/WhatsApp) para documentos por vencer y
  mantenimientos programados.
- Despliegue: hoy se abre el HTML directamente o se sirve como archivo estático;
  definir dónde se aloja para uso real del equipo (hosting propio, Vercel, etc.).
