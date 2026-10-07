-- =====================================================================
-- TRAZA — Esquema de base de datos para Supabase (schema aislado)
-- Pega y ejecuta este archivo completo en: Supabase > SQL Editor > New query
--
-- Todo vive dentro del schema "traza", separado de "public", para no
-- chocar con tablas que ya tengas en este proyecto. Después de correr
-- este script, sigue el paso "Exponer el schema" en SETUP.md — es
-- obligatorio, si no la app no podrá leer estas tablas.
-- =====================================================================

create extension if not exists "pgcrypto";
create schema if not exists traza;

-- Acceso base al schema (las políticas RLS de más abajo deciden qué
-- filas ve cada quién; esto solo habilita el schema como tal).
grant usage on schema traza to anon, authenticated, service_role;
alter default privileges for role postgres in schema traza grant all on tables to anon, authenticated, service_role;
alter default privileges for role postgres in schema traza grant all on routines to anon, authenticated, service_role;

-- ---------------------------------------------------------------------
-- 1. PERFILES DE USUARIO Y ROLES
-- ---------------------------------------------------------------------
create table if not exists traza.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  role text not null default 'solo_lectura' check (role in ('admin','operaciones','solo_lectura')),
  created_at timestamptz default now()
);

-- Permisos granulares por usuario (opcional, encima de los 3 roles base):
-- si custom_access es true, el usuario solo ve los módulos/menús/submenús
-- marcados en allowed_modules, sin importar su rol (salvo admin, que
-- siempre ve todo). areas es solo una etiqueta organizativa del usuario.
alter table traza.profiles
  add column if not exists custom_access boolean default false,
  add column if not exists allowed_modules jsonb default '{}'::jsonb,
  add column if not exists areas text[] default '{}';

-- Lugares (sedes) asignados a un usuario, para autocompletar el campo
-- Lugar/Sede/Ciudad en los formularios. Un admin tiene acceso a todos los
-- lugares sin necesidad de tenerlos listados aquí (ver isAdmin() en el
-- cliente). Reusa los valores del catálogo 'sede'.
alter table traza.profiles
  add column if not exists lugares text[] default '{}';

-- Rol 'conductor': cuenta liviana para que el chofer reporte fallas de su
-- unidad desde el celular (ver traza.fault_reports más abajo). No se agrega
-- a can_write() — solo puede crear/ver sus propios reportes, nada más.
alter table traza.profiles drop constraint if exists profiles_role_check;
alter table traza.profiles add constraint profiles_role_check check (role in ('admin','operaciones','solo_lectura','conductor'));

-- Cuando alguien se registra (auth.users), se le crea automáticamente
-- un perfil con rol 'solo_lectura'. El primer admin se promueve a mano
-- (ver SETUP.md).
create or replace function traza.handle_new_user()
returns trigger as $$
begin
  insert into traza.profiles (id, full_name, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', new.email), 'solo_lectura');
  return new;
end;
$$ language plpgsql security definer set search_path = traza, pg_temp;

-- Nombre de trigger único (con sufijo _traza) para no chocar con
-- triggers que ya tengas en este proyecto sobre auth.users.
drop trigger if exists on_auth_user_created_traza on auth.users;
create trigger on_auth_user_created_traza
  after insert on auth.users
  for each row execute procedure traza.handle_new_user();

-- Esta función SOLO debe ejecutarse como trigger de auth.users (arriba),
-- nunca invocada directamente por un usuario vía API. Le revocamos el
-- permiso de ejecución directa (reportado por el linter de seguridad de
-- Supabase: "anon/authenticated_security_definer_function_executable").
revoke execute on function traza.handle_new_user() from public, anon, authenticated;

-- Funciones auxiliares para las políticas de acceso (RLS). Necesitan
-- quedar ejecutables por "authenticated" porque las políticas RLS las
-- llaman en el contexto del usuario que hace la consulta — si se les
-- quita ese permiso, dejan de funcionar los filtros de toda la app.
create or replace function traza.is_admin()
returns boolean as $$
  select exists (select 1 from traza.profiles where id = auth.uid() and role = 'admin');
$$ language sql security definer stable set search_path = traza, pg_temp;

create or replace function traza.can_write()
returns boolean as $$
  select exists (select 1 from traza.profiles where id = auth.uid() and role in ('admin','operaciones'));
$$ language sql security definer stable set search_path = traza, pg_temp;

-- A propósito NO incluido en can_write(): un Conductor solo puede tocar
-- traza.fault_reports (políticas propias, no la plantilla genérica de más
-- abajo), nunca el resto de tablas operativas.
create or replace function traza.is_conductor()
returns boolean as $$
  select exists (select 1 from traza.profiles where id = auth.uid() and role = 'conductor');
$$ language sql security definer stable set search_path = traza, pg_temp;

-- No necesitan ser invocables directamente por un usuario anónimo (sin
-- sesión) — solo por "authenticated", que es quien las usa dentro de las
-- políticas RLS al hacer una consulta ya logueado.
revoke execute on function traza.is_admin() from public, anon;
revoke execute on function traza.can_write() from public, anon;
revoke execute on function traza.is_conductor() from public, anon;
grant execute on function traza.is_admin() to authenticated;
grant execute on function traza.can_write() to authenticated;
grant execute on function traza.is_conductor() to authenticated;

-- ---------------------------------------------------------------------
-- 2. TABLAS OPERATIVAS (todas dentro de traza.*)
-- ---------------------------------------------------------------------
create table if not exists traza.vehicles (
  id uuid primary key default gen_random_uuid(),
  plate text unique not null,
  brand text, model text, type text, year int,
  status text default 'Operativo',
  km int default 0,
  soat_expiry date,
  revision_expiry date,
  base text,
  driver_id uuid,
  created_at timestamptz default now()
);

-- Un vehículo puede tener hasta 2 conductores asignados (ej. turnos o
-- piloto/copiloto habitual).
alter table traza.vehicles add column if not exists driver_id_2 uuid;

-- Campos adicionales de ficha técnica (se agregan con ALTER para que
-- también funcione si vuelves a correr este script sobre una base que
-- ya tenía la tabla vehicles creada con la versión anterior).
alter table traza.vehicles
  add column if not exists internal_number text,
  add column if not exists body_type text,
  add column if not exists passengers int,
  add column if not exists distribution text,
  add column if not exists serial_number text,
  add column if not exists engine_number text,
  add column if not exists wheel_formula text,
  add column if not exists wheels int,
  add column if not exists axles int,
  add column if not exists net_weight numeric,
  add column if not exists gross_weight numeric,
  add column if not exists payload numeric,
  add column if not exists length numeric,
  add column if not exists width numeric,
  add column if not exists height numeric,
  add column if not exists service text,
  add column if not exists operation text,
  add column if not exists circulation_card_expiry date,
  add column if not exists km_updated_at timestamptz;

create table if not exists traza.drivers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  license text,
  license_expiry date,
  status text default 'Activo',
  vehicle_plate text,
  phone text,
  created_at timestamptz default now()
);

-- Vincula la cuenta de un usuario con rol 'conductor' a su fila en drivers,
-- para autocompletar su nombre en el reporte de falla sin que lo escriba.
alter table traza.profiles add column if not exists driver_id uuid references traza.drivers(id) on delete set null;

create table if not exists traza.maintenance (
  id uuid primary key default gen_random_uuid(),
  plate text not null,
  kind text,
  description text,
  date date default now(),
  cost numeric default 0,
  status text default 'Programado',
  next_due_km int,
  created_at timestamptz default now()
);

alter table traza.maintenance
  add column if not exists next_due_date date,
  add column if not exists km_done int,
  add column if not exists cycle_type text,
  add column if not exists place text,
  add column if not exists component text,
  add column if not exists responsible text,
  add column if not exists observations text,
  add column if not exists ot_number int;

-- ---------------------------------------------------------------------
-- VIDA DE COMPONENTES — km de vida proyectado por tipo de componente
-- (catálogo 'componente'), para alertar cuándo toca cambiarlo por
-- vehículo según su historial de Correctivos.
-- ---------------------------------------------------------------------
create table if not exists traza.component_life_config (
  id uuid primary key default gen_random_uuid(),
  component text not null unique,
  projected_km int not null,
  created_at timestamptz default now()
);

-- Excepción por placa: si existe, reemplaza el km de vida proyectado
-- general de component_life_config para esa unidad puntual.
create table if not exists traza.component_life_overrides (
  id uuid primary key default gen_random_uuid(),
  plate text not null,
  component text not null,
  projected_km int not null,
  created_at timestamptz default now(),
  unique(plate, component)
);

-- ---------------------------------------------------------------------
-- CICLOS DE MANTENIMIENTO (secuencia tipo S-S-M-S-S-L que se repite,
-- cada uno cada N km). Cada vehículo tiene asignado, como máximo, un ciclo.
-- ---------------------------------------------------------------------
create table if not exists traza.maintenance_cycles (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  interval_km int not null,
  sequence text not null, -- ej. "S,S,M,S,S,L"
  created_at timestamptz default now()
);

alter table traza.vehicles
  add column if not exists cycle_id uuid references traza.maintenance_cycles(id);

-- Tareas de cada tipo dentro de un ciclo (ej. tipo "S" del Ciclo Scania K410
-- incluye: cambiar aceite de motor, cambiar filtro de combustible, etc.)
create table if not exists traza.maintenance_cycle_tasks (
  id uuid primary key default gen_random_uuid(),
  cycle_id uuid not null references traza.maintenance_cycles(id) on delete cascade,
  type_label text not null,
  task text not null,
  sort_order int default 0,
  created_at timestamptz default now()
);

-- Repuestos necesarios por cada tipo de mantenimiento dentro de un ciclo
-- (ej. Tipo "S": 8 galones de aceite, 1 filtro de aceite, 1 filtro de aire)
create table if not exists traza.maintenance_cycle_parts (
  id uuid primary key default gen_random_uuid(),
  cycle_id uuid not null references traza.maintenance_cycles(id) on delete cascade,
  type_label text not null,
  product_name text not null,
  quantity numeric default 1,
  unit text,
  sort_order int default 0,
  created_at timestamptz default now()
);

-- ---------------------------------------------------------------------
-- ÓRDENES DE TRABAJO (OT)
-- ---------------------------------------------------------------------
create table if not exists traza.work_orders (
  id uuid primary key default gen_random_uuid(),
  ot_number int not null,
  created_at timestamptz default now()
);

-- Se agregan con ALTER (no dentro del CREATE) para que, si la tabla ya
-- existía de un intento anterior con menos columnas, esta parte igual
-- las complete — CREATE TABLE IF NOT EXISTS no agrega columnas nuevas
-- a una tabla que ya existe.
alter table traza.work_orders
  add column if not exists ot_number int,
  add column if not exists requested_jobs_list text,   -- "N° TRAB": lista de trabajos solicitados, uno por línea
  add column if not exists start_date date,
  add column if not exists place text,                 -- catálogo ciudad
  add column if not exists plate text,
  add column if not exists km int,
  add column if not exists driver_id uuid,              -- piloto
  add column if not exists requested_work text,         -- trabajos solicitados y/o falla (narrativa)
  add column if not exists area text,                   -- Carrocería / Eléctrica / Mecánica
  add column if not exists system text,                 -- catálogo sistema_ot
  add column if not exists maintenance_type text,       -- Preventivo / Correctivo
  add column if not exists responsible text,            -- catálogo personal
  add column if not exists work_done text,               -- trabajo realizado (maestro de trabajos o libre)
  add column if not exists component text,              -- catálogo componente
  add column if not exists status text default 'Programado',
  add column if not exists end_date date,
  add column if not exists labor_cost numeric default 0,
  add column if not exists parts_cost numeric default 0,
  add column if not exists total_cost numeric default 0,
  add column if not exists observations text;

alter table traza.work_orders drop constraint if exists work_orders_ot_number_key;
alter table traza.work_orders add constraint work_orders_ot_number_key unique (ot_number);

-- Estado de la OT (Abierta/Cerrada) es independiente del estado de cada
-- trabajo solicitado. La fecha/hora de apertura se registra sola al crear
-- la OT; el cierre queda con su propia marca de tiempo.
alter table traza.work_orders
  add column if not exists status text default 'Abierta',
  add column if not exists start_datetime timestamptz default now(),
  add column if not exists closed_at timestamptz;

-- Taller propio (por defecto) vs. taller externo. Solo cuando es externo
-- se activa el desglose de costo por trabajo realizado (mano de obra +
-- repuestos con costo individual); en taller propio se mantiene el
-- registro simple de siempre.
alter table traza.work_orders add column if not exists workshop_type text default 'PROPIO';

-- Por si la columna "status" ya existía de un diseño anterior con una
-- restricción check (ej. limitada a Programado/En Proceso/...), la
-- quitamos para permitir los valores actuales: Abierta / Cerrada.
do $$
declare
  con text;
begin
  for con in
    select conname from pg_constraint
    where conrelid = 'traza.work_orders'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%status%'
  loop
    execute format('alter table traza.work_orders drop constraint %I', con);
  end loop;
end $$;

-- Por si la tabla ya existía con columnas de un diseño anterior que ya no
-- se usan (ej. una "description" obligatoria), les quitamos la restricción
-- de "no nulo" para que no bloqueen los inserts nuevos. No falla si la
-- columna no existe.
do $$
declare
  col text;
begin
  foreach col in array array['description','kind','cost','date']
  loop
    if exists (
      select 1 from information_schema.columns
      where table_schema='traza' and table_name='work_orders' and column_name=col
    ) then
      execute format('alter table traza.work_orders alter column %I drop not null', col);
    end if;
  end loop;
end $$;

-- Cada trabajo solicitado dentro de una OT tiene su propia área, sistema,
-- tipo de mantenimiento, responsable, trabajo realizado, componente,
-- estado y costos (en vez de un solo set de estos campos por toda la OT).
create table if not exists traza.work_order_items (
  id uuid primary key default gen_random_uuid(),
  work_order_id uuid not null references traza.work_orders(id) on delete cascade,
  requested_job text not null,
  area text,
  system text,
  maintenance_type text,
  responsible text,
  work_done text,
  component text,
  status text default 'Programado',
  labor_cost numeric default 0,
  parts_cost numeric default 0,
  total_cost numeric default 0,
  sort_order int default 0,
  created_at timestamptz default now()
);

alter table traza.work_order_items add column if not exists observations text;

-- Desglose de costo (mano de obra + repuestos con su costo) por cada
-- "trabajo realizado" dentro de un ítem. work_done sigue siendo el texto
-- plano (uno por línea) que ya usan el buscador, la cartilla y las tablas;
-- este campo es el detalle estructurado para el desglose de costos.
alter table traza.work_order_items add column if not exists work_done_details jsonb;

-- ---------------------------------------------------------------------
-- PROGRAMADOS — cola de trabajos de mantenimiento (por ciclo o por
-- componente) que se "programan" desde Estado de ciclos / Estado por
-- componente, se asignan a una OT (existente o nueva), y al cerrarse esa
-- OT con el trabajo Terminado, generan solos el registro de
-- mantenimiento correspondiente (reseteando el próximo cambio).
-- ---------------------------------------------------------------------
create table if not exists traza.scheduled_maintenance (
  id uuid primary key default gen_random_uuid(),
  source_type text not null check (source_type in ('ciclo','componente')),
  plate text not null,
  cycle_type text,
  component text,
  description text not null,
  scheduled_date date default now(),
  status text not null default 'Programado' check (status in ('Programado','Asignado a OT','Completado','Cancelado')),
  work_order_id uuid references traza.work_orders(id) on delete set null,
  work_order_item_id uuid references traza.work_order_items(id) on delete set null,
  created_at timestamptz default now()
);

alter table traza.scheduled_maintenance add column if not exists place text;

create table if not exists traza.fuel_logs (
  id uuid primary key default gen_random_uuid(),
  plate text not null,
  date date default now(),
  liters numeric,
  price_per_liter numeric,
  cost numeric,
  station text,
  odometer int,
  created_at timestamptz default now()
);

alter table traza.fuel_logs
  add column if not exists voucher_number text,
  add column if not exists time text,
  add column if not exists route text,
  add column if not exists pilot_id uuid,
  add column if not exists copilot_id uuid,
  add column if not exists gallons numeric,
  add column if not exists ppg numeric,
  add column if not exists is_full_tank boolean default false,
  add column if not exists km_reco numeric,
  add column if not exists kpg numeric,
  add column if not exists city text,
  add column if not exists supplier text;

alter table traza.fuel_logs
  add column if not exists fuel_type text,
  add column if not exists supplier text,
  add column if not exists voucher_number text;

-- Algunos abastecimientos son para taller (lavado de piezas, u otro uso)
-- y no corresponden a ninguna placa de la flota.
alter table traza.fuel_logs alter column plate drop not null;
alter table traza.fuel_logs add column if not exists destination text;
alter table traza.fuel_logs add column if not exists observations text;

-- Cada fila de traza.tires es un neumático físico persistente, identificado
-- por su "code" único (no por placa/posición) — a diferencia del diseño
-- anterior, donde la fila representaba una posición y se reescribía con
-- cada neumático nuevo. Un neumático recorre un ciclo de vida real:
--   Almacen -> Montado -> (al desmontar) Almacen | Reencauche | Cementerio
--   Reencauche -> Almacen (con retread_gen +1, cuando vuelve reencauchado)
-- plate/position solo tienen valor mientras status='Montado'; el resto del
-- tiempo el neumático existe igual (en almacén o en camino a reencauche)
-- pero no está en ninguna unidad.
create table if not exists traza.tires (
  id uuid primary key default gen_random_uuid(),
  code text,
  status text not null default 'Almacen' check (status in ('Almacen','Montado','Reencauche','Cementerio')),
  plate text,
  position text,
  brand text,
  serial text,
  size text,
  design text,
  retread_gen int default 0,
  supplier text,
  guide_number text,
  invoice_number text,
  cost numeric default 0,
  initial_tread_mm numeric,
  install_date date,
  mount_km int,
  estado text default 'Bueno',
  created_at timestamptz default now()
);
-- unique(code) solo cuando code no es null: permite dejar el campo vacío
-- en datos viejos/migrados sin bloquear inserts, pero no permite dos
-- neumáticos activos con el mismo código.
create unique index if not exists idx_tires_code on traza.tires(code) where code is not null;

-- Por si traza.tires ya existía de una versión anterior (donde la fila
-- representaba una posición y plate era obligatorio): agrega status y
-- libera plate/position para que un neumático pueda existir sin estar
-- montado en ninguna unidad.
alter table traza.tires alter column plate drop not null;
alter table traza.tires add column if not exists status text default 'Almacen';
alter table traza.tires drop constraint if exists tires_status_check;
alter table traza.tires add constraint tires_status_check check (status in ('Almacen','Montado','Reencauche','Cementerio'));

drop table if exists traza.tire_changes;
-- Historial de eventos del neumático (ingreso, montaje, desmontaje, envío
-- y retorno de reencauche, baja) — el "hoja de vida" real de cada
-- neumático, ahora que es una entidad persistente y no algo atado a una
-- posición. plate/position/km quedan vacíos en eventos donde no aplican
-- (ingreso, envío a reencauche, baja).
create table if not exists traza.tire_events (
  id uuid primary key default gen_random_uuid(),
  tire_id uuid not null references traza.tires(id) on delete cascade,
  event_type text not null check (event_type in ('Ingreso','Montaje','Desmontaje','Envio a reencauche','Retorno de reencauche','Baja')),
  plate text,
  position text,
  km int,
  cost numeric,
  event_date date default now(),
  reason text,
  created_at timestamptz default now()
);
create index if not exists idx_tire_events_tire on traza.tire_events(tire_id);

-- ---------------------------------------------------------------------
-- Control de cocadas: mediciones periódicas de profundidad de banda (3
-- puntos) para proyectar cuándo hay que retirar el neumático —
-- equivalente a la hoja "REPORTES" del Excel de control. Referencia
-- tires.id directo (a diferencia del diseño anterior) porque ahora esa
-- fila SÍ es el mismo neumático físico durante toda su vida; plate/
-- position/tire_code quedan como copia de conveniencia para mostrar sin
-- tener que hacer join.
-- ---------------------------------------------------------------------
create table if not exists traza.tire_inspections (
  id uuid primary key default gen_random_uuid(),
  tire_id uuid references traza.tires(id) on delete cascade,
  plate text not null,
  position text not null,
  tire_code text,
  inspection_date date default now(),
  inspection_km int,
  tread_left_mm numeric,
  tread_center_mm numeric,
  tread_right_mm numeric,
  psi numeric,
  route text,
  created_at timestamptz default now()
);
create index if not exists idx_tire_inspections_plate_pos on traza.tire_inspections(plate, position);
-- Por si tire_inspections ya existía de la versión anterior (sin tire_id).
alter table traza.tire_inspections add column if not exists tire_id uuid references traza.tires(id) on delete cascade;
create index if not exists idx_tire_inspections_tire on traza.tire_inspections(tire_id);

-- ---------------------------------------------------------------------
-- ASISTENCIA Y LIQUIDACIÓN DE PILOTOS (a partir del Excel de asistencia)
-- ---------------------------------------------------------------------

-- Maestro de rutas fijas con tarifa (distinto de "routes", que es viajes
-- puntuales programados). Aquí van las ~50 rutas fijas con su km, horas
-- y pago por viaje realizado.
create table if not exists traza.route_rates (
  id uuid primary key default gen_random_uuid(),
  route_name text not null unique,
  km numeric,
  hours numeric,
  pay_per_trip numeric default 0,
  created_at timestamptz default now()
);

alter table traza.route_rates add column if not exists type text;

-- Rutas fijas extraídas del maestro real de la empresa (editable luego)
insert into traza.route_rates (route_name, km, hours, pay_per_trip) values
  ('PIURA-BAGUA', 440, 10.0, 20.0),
  ('BAGUA-PIURA', 440, 10.0, 20.0),
  ('TARAPOTO-TRUJILLO', 915, 18.0, 43.0),
  ('TRUJILLO-TARAPOTO', 915, 18.0, 43.0),
  ('CAJAMARCA-LIMA', 865, 16.0, 37.0),
  ('LIMA-CAJAMARCA', 865, 16.0, 37.0),
  ('MINA GOLDFIELD', 170, 5.0, 44.0),
  ('MINA COIMOLACHE', 180, 5.5, 46.0),
  ('PIURA-TARAPOTO', 790, 16.0, 37.0),
  ('TARAPOTO-PIURA', 790, 16.0, 37.0),
  ('MOYOBAMBA-TRUJILLO', 825, 15.5, 39.0),
  ('TRUJILLO-MOYOBAMBA', 825, 15.5, 39.0),
  ('CHACHAPOYAS-TRUJILLO', 660, 14.0, 32.0),
  ('CHICLAYO-TARAPOTO', 750, 14.0, 35.0),
  ('TARAPOTO-CHICLAYO', 750, 14.0, 35.0),
  ('TRUJILLO-CHACHAPOYAS', 660, 14.0, 32.0),
  ('MOYOBAMBA-PIURA', 680, 13.5, 32.0),
  ('PIURA-MOYOBAMBA', 680, 13.5, 32.0),
  ('CHICLAYO-LIMA', 770, 13.0, 31.0),
  ('LIMA-CHICLAYO', 770, 13.0, 31.0),
  ('CHEPEN-LIMA', 700, 12.0, 28.0),
  ('LIMA-CHEPEN', 700, 12.0, 28.0),
  ('JAEN-TRUJILLO', 500, 10.0, 22.0),
  ('TRUJILLO-JAEN', 500, 10.0, 22.0),
  ('CAJAMARCA-PIURA', 487, 9.0, 21.0),
  ('LIMA-TRUJILLO', 565, 10.0, 23.0),
  ('PIURA-CAJAMARCA', 475, 9.0, 21.0),
  ('TRUJILLO-LIMA', 565, 10.0, 23.0),
  ('DELEGACION', 600, 8.0, 20.0),
  ('JAEN-TARAPOTO', 435, 8.0, 21.0),
  ('TARAPOTO-JAEN', 435, 8.0, 21.0),
  ('JAEN-PIURA', 370, 7.0, 17.0),
  ('PIURA-JAEN', 370, 7.0, 17.0),
  ('PIURA-TRUJILLO', 425, 8.0, 17.0),
  ('TRUJILLO-PIURA', 425, 8.0, 17.0),
  ('TRUJILLO-BAGUA', 580, 12.0, 26.0),
  ('BAGUA-TRUJILLO', 580, 12.0, 26.0),
  ('CAJAMARCA-CHICLAYO', 265, 6.0, 14.0),
  ('CAJAMARCA-TRUJILLO', 300, 6.0, 15.0),
  ('CHICLAYO-CAJAMARCA', 265, 6.0, 14.0),
  ('CHICLAYO-JAEN', 300, 6.0, 15.0),
  ('JAEN-CHICLAYO', 300, 6.0, 15.0),
  ('TRUJILLO-CAJAMARCA', 300, 6.0, 15.0),
  ('CHICLAYO-TRUJILLO', 210, 4.0, 9.0),
  ('TRUJILLO-CHICLAYO', 210, 4.0, 9.0),
  ('PIURA-CHICLAYO', 220, 4.0, 9.0),
  ('CHICLAYO-PIURA', 220, 4.0, 9.0),
  ('MINA ZANJA', 200, 6.5, 55.0),
  ('MINA HUANDOY', 80, 2.5, 22.0),
  ('MINA SHAHUINDO', 260, 8.0, 69.0),
  ('DESCANSO DIFERIDO', null, null, null),
  ('DESCANSO', null, null, null),
  ('FALTO', null, null, null),
  ('DESCANSO MEDICO', null, null, null),
  ('SUSPENSION', null, null, null),
  ('LICENCIA', null, null, null),
  ('VACACIONES', null, null, null),
  ('TRUJILLO', null, null, null),
  ('LIMA', null, null, null),
  ('CAJAMARCA', null, null, null),
  ('PIURA', null, null, null),
  ('CHICLAYO', null, null, null),
  ('TARAPOTO', null, null, null),
  ('JAEN', null, null, null),
  ('CHACHAPOYAS', null, null, null),
  ('PACASMAYO', null, null, null),
  ('FIN DE CONTRATO', null, null, null),
  ('CHEPEN', null, null, null),
  ('BAGUA', null, null, null),
  ('PARO', null, null, null),
  ('CHIMBOTE', null, null, null),
  ('NUEVO INGRESO', null, null, null),
  ('DELEGACION', null, null, null)
on conflict (route_name) do nothing;


-- Un registro por conductor por día. status='Trabajado' habilita
-- placa/ruta de viaje 1 y 2 (opcional el segundo). El resto de status
-- son los días "no trabajados" que se cuentan en el resumen mensual.
create table if not exists traza.driver_attendance (
  id uuid primary key default gen_random_uuid(),
  driver_id uuid not null references traza.drivers(id) on delete cascade,
  date date not null,
  plate text,
  status text not null default 'Trabajado' check (status in ('Trabajado','Descanso','Falta','Descanso Medico','Suspension','Licencia','Vacaciones','Delegado')),
  route_trip1 text,
  route_trip2 text,
  created_at timestamptz default now(),
  unique(driver_id, date)
);

-- Componentes fijos/mensuales del sueldo por conductor (se editan a
-- mano; el monto por rutas se calcula solo desde driver_attendance).
create table if not exists traza.driver_payroll_config (
  id uuid primary key default gen_random_uuid(),
  driver_id uuid not null references traza.drivers(id) on delete cascade unique,
  base_salary numeric default 0,
  family_allowance numeric default 0,
  fuel_bonus numeric default 0,
  service_bonus numeric default 0,
  viatico_bonus numeric default 0,
  created_at timestamptz default now()
);

-- ---------------------------------------------------------------------
-- HISTORIAL DE KILOMETRAJES — registros manuales de km por placa y fecha
-- (módulo Mantenimiento > Kilometrajes). Independiente de Combustible/OT,
-- para poder consultar el km de una fecha específica hacia atrás y no
-- perder la fecha real del dato (antes se sobreescribía vehicles.km sin
-- guardar historial, y siempre quedaba con la fecha "de hoy").
create table if not exists traza.vehicle_km_logs (
  id uuid primary key default gen_random_uuid(),
  plate text not null,
  date date not null,
  km integer not null,
  notes text,
  created_at timestamptz default now()
);
create index if not exists idx_vehicle_km_logs_plate_date on traza.vehicle_km_logs(plate, date);

create table if not exists traza.routes (
  id uuid primary key default gen_random_uuid(),
  plate text not null,
  origin text, destination text,
  date date default now(),
  distance_km int,
  status text default 'Programada',
  created_at timestamptz default now()
);

alter table traza.routes
  add column if not exists route_name text,
  add column if not exists driver_id uuid references traza.drivers(id) on delete set null,
  add column if not exists co_driver_id uuid references traza.drivers(id) on delete set null;

create table if not exists traza.checklists (
  id uuid primary key default gen_random_uuid(),
  plate text not null,
  date date default now(),
  items jsonb,
  status text default 'Conforme',
  created_at timestamptz default now()
);
-- Nombre de la plantilla usada (Pasajeros Interprovincial / Carga / Personal
-- a Mina) según la Operación del vehículo al momento de la inspección — se
-- guarda tal cual para que el historial no cambie si luego se ajustan las
-- plantillas en el código.
alter table traza.checklists add column if not exists service_label text;
-- Código del formato oficial usado (FOR-OPS-042 / FOR-OPS-043 / FOR-SST-088),
-- los campos de cabecera propios de esa plantilla (conductor, licencia, guía
-- de remisión, alcotest, etc.) y las observaciones/hallazgos en texto libre.
alter table traza.checklists
  add column if not exists code text,
  add column if not exists header jsonb default '{}'::jsonb,
  add column if not exists observations text;

create table if not exists traza.inventory (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  unit text,
  min_stock int default 0,
  cost numeric default 0,
  stock int default 0,
  created_at timestamptz default now()
);

create table if not exists traza.purchase_orders (
  id uuid primary key default gen_random_uuid(),
  supplier text,
  item text,
  qty int,
  total numeric,
  date date default now(),
  status text default 'Pendiente',
  created_at timestamptz default now()
);

-- ---------------------------------------------------------------------
-- LOGÍSTICA — Orden de Compra: la cabecera vive en purchase_orders
-- (las columnas de arriba quedan sin usar; las nuevas son las que
-- alimenta el formulario de Orden de Compra), con sus ítems en
-- purchase_order_items, y dos maestros reutilizables: proveedores
-- (por RUC o nombre) y productos (con su código, código de fabricante
-- y unidad de medida ya fijos).
-- ---------------------------------------------------------------------
alter table traza.purchase_orders
  add column if not exists po_number int,
  add column if not exists supplier_ruc text,
  add column if not exists supplier_name text,
  add column if not exists voucher_type text,
  add column if not exists payment_method text,
  add column if not exists credit_days int,
  add column if not exists currency text,
  add column if not exists authorizer text,
  add column if not exists order_date date,
  add column if not exists delivery_date date,
  add column if not exists ship_to text,
  add column if not exists locked boolean default false,
  add column if not exists includes_igv boolean default true;

alter table traza.purchase_orders drop constraint if exists purchase_orders_po_number_key;
alter table traza.purchase_orders add constraint purchase_orders_po_number_key unique (po_number);

create table if not exists traza.purchase_order_items (
  id uuid primary key default gen_random_uuid(),
  purchase_order_id uuid not null references traza.purchase_orders(id) on delete cascade,
  code text,
  oem_code text,
  product_name text,
  unit text,
  cost_center text,
  quantity numeric,
  unit_cost numeric,
  subtotal numeric,
  sort_order int default 0,
  created_at timestamptz default now()
);

create table if not exists traza.suppliers (
  id uuid primary key default gen_random_uuid(),
  ruc text,
  name text,
  created_at timestamptz default now()
);

alter table traza.suppliers
  add column if not exists address text,
  add column if not exists contact text,
  add column if not exists phone text;

create table if not exists traza.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  code text,
  oem_code text,
  unit text,
  created_at timestamptz default now(),
  unique(name)
);

alter table traza.products
  add column if not exists product_type text,
  add column if not exists category text,
  add column if not exists subcategory text,
  add column if not exists brand text;

-- Un mismo nombre de producto (ej. "MANGUERA HIDRAULICA") puede repetirse si
-- cambia la marca o el código de fabricante. La identidad deja de ser solo el
-- nombre y pasa a ser nombre + marca + código de fabricante (los datos
-- existentes la cumplen porque antes el nombre ya era único).
alter table traza.products drop constraint if exists products_name_key;
create unique index if not exists products_identity_key on traza.products
  (upper(name), coalesce(upper(brand),''), coalesce(upper(oem_code),''));

-- Inventario: se maneja directamente sobre el maestro de Productos (en vez
-- de una tabla aparte) para no duplicar datos. El stock se descuenta solo
-- cuando se despacha un pedido en Orden Logística.
alter table traza.products
  add column if not exists stock numeric default 0,
  add column if not exists min_stock numeric default 0,
  add column if not exists cost numeric default 0;

-- Servicios: maestro separado de Productos porque un servicio (mano de obra
-- de terceros, inspecciones, etc.) no maneja stock/almacén — solo código,
-- unidad (ej. "Global", "Hora") y costo referencial, para poder elegirlo en
-- Orden de Compra igual que un producto.
create table if not exists traza.services (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  code text,
  unit text,
  cost numeric default 0,
  created_at timestamptz default now(),
  unique(name)
);

-- Clasificación de Servicios: mismo árbol Tipo/Categoría que Productos (ver
-- PRODUCT_TAXONOMY), pero sin Subcategoría — un servicio no la necesita.
alter table traza.services
  add column if not exists product_type text,
  add column if not exists category text;

-- "SERVICIOS" ya no es una subcategoría válida de Producto (se movió a su
-- propio árbol de Servicios) — limpia cualquier producto que ya la tuviera.
update traza.products set subcategory = null where subcategory = 'SERVICIOS';

-- Un ítem de Orden de Compra ahora puede ser Producto o Servicio.
-- item_type default 'PRODUCTO' para que todas las filas ya existentes
-- sigan interpretándose igual que antes. cost_center se llena solo para
-- Servicio (un producto pasa primero por almacén vía Comprobante de Pago
-- o manual, y su centro de costo se define después al despacharlo por
-- Orden Logística).
alter table traza.purchase_order_items
  add column if not exists item_type text default 'PRODUCTO' check (item_type in ('PRODUCTO','SERVICIO')),
  add column if not exists service_id uuid references traza.services(id) on delete set null;

-- Enlace opcional de un ítem de Servicio a una OT (y, dentro de ella, a un
-- trabajo específico) para que su costo se cargue a esa OT en cuanto su
-- comprobante quede registrado — igual que ya pasa con logistics_orders.
-- work_order_number (no una FK a work_orders.id) para poder guardar el
-- enlace aunque la OT cambie de id en algún reseed, igual que el patrón
-- ya usado en logistics_orders.work_order_number.
alter table traza.purchase_order_items
  add column if not exists work_order_number int,
  add column if not exists work_order_item_id uuid references traza.work_order_items(id) on delete set null;

-- Enlace opcional a nivel de CABECERA de OC: si la OC completa está
-- anexada a una OT, todos sus ítems heredan ese N° de OT y el centro de
-- costo (la placa de esa OT), sin tener que repetirlo ítem por ítem.
alter table traza.purchase_orders
  add column if not exists work_order_number int;

-- Enlace opcional de un ítem de Servicio a un neumático en Reencauche: al
-- registrar el Comprobante de esa OC, su costo real (con IGV) completa
-- automáticamente el "Retorno de reencauche" de ese neumático (ver
-- completeTireRetreadFromPoItem) en vez de tipearlo a mano en Neumáticos.
-- costCenter/workOrderNumber quedan null en estos ítems a propósito — el
-- gasto se atribuye vía el neumático (tireSpendEvents), no por centro de
-- costo, para no contarlo dos veces en Gastos por Centro de Costo.
alter table traza.purchase_order_items
  add column if not exists tire_id uuid references traza.tires(id) on delete set null;

-- source_po_item_id en tire_events: permite revertir el "Retorno de
-- reencauche" generado automáticamente si el Comprobante que lo originó se
-- elimina después (ver el borrado de Comprobantes de Pago).
alter table traza.tire_events
  add column if not exists source_po_item_id uuid references traza.purchase_order_items(id) on delete set null;

-- Tipo de cambio (soles por dólar) para OC en Dólares — se captura por OC,
-- no un valor global, porque cada compra real tiene su propio tipo de
-- cambio del día. Se usa para convertir el costo de esa OC a soles al
-- sumarlo en OTs y reportes; sin este dato, esos ítems quedan excluidos
-- de esas sumas (no se asume un tipo de cambio). Las OC en dólares que ya
-- existían antes de este campo quedan con exchange_rate null a propósito.
alter table traza.purchase_orders
  add column if not exists exchange_rate numeric;

-- ---------------------------------------------------------------------
-- LOGÍSTICA — Orden Logística: pedidos internos de material, con
-- despacho por ítem (Pendiente / Despachado / Rechazado) y su propio
-- vale de despacho imprimible.
-- ---------------------------------------------------------------------
create table if not exists traza.logistics_orders (
  id uuid primary key default gen_random_uuid(),
  lo_number int,
  requested_at timestamptz default now(),
  place text,
  responsible text,
  area text,
  work_order_number int,
  voided boolean default false,
  created_at timestamptz default now(),
  unique(lo_number)
);

alter table traza.logistics_orders
  add column if not exists plate text,
  add column if not exists priority text default 'Normal',
  add column if not exists void_reason text;

-- Secuencia para lo_number: antes se calculaba en el cliente (max+1), lo que
-- causaba "duplicate key value violates unique constraint
-- logistics_orders_lo_number_key" cuando dos usuarios creaban una Orden
-- Logística casi al mismo tiempo. Ahora la BD asigna el número de forma
-- atómica. Seguro de re-correr: siempre reubica la secuencia en base al
-- máximo actual.
create sequence if not exists traza.logistics_orders_lo_number_seq;
alter sequence traza.logistics_orders_lo_number_seq owned by traza.logistics_orders.lo_number;
alter table traza.logistics_orders alter column lo_number set default nextval('traza.logistics_orders_lo_number_seq');
do $$ begin
  perform setval('traza.logistics_orders_lo_number_seq', coalesce((select max(lo_number) from traza.logistics_orders), 0) + 1, false);
end $$;
grant usage, select on traza.logistics_orders_lo_number_seq to anon, authenticated, service_role;

create table if not exists traza.logistics_order_items (
  id uuid primary key default gen_random_uuid(),
  logistics_order_id uuid not null references traza.logistics_orders(id) on delete cascade,
  quantity numeric,
  unit text,
  description text,
  cost_center text,
  observations text,
  status text default 'Pendiente',
  dispatched_at timestamptz,
  sort_order int default 0,
  created_at timestamptz default now()
);

-- ---------------------------------------------------------------------
-- product_id en ítems de compra y logística: antes el cruce con el
-- maestro de Productos para sumar/restar stock (Comprobantes de Pago,
-- despacho de Orden Logística) se hacía solo por código o por nombre en
-- mayúscula, lo que fallaba en silencio si un producto se renombraba o
-- quedaba duplicado. El frontend ahora guarda también el id al crear un
-- ítem, y lo usa como primer criterio de match (código/nombre quedan
-- como respaldo para filas creadas antes de este cambio).
-- ---------------------------------------------------------------------
alter table traza.purchase_order_items add column if not exists product_id uuid references traza.products(id) on delete set null;
alter table traza.logistics_order_items add column if not exists product_id uuid references traza.products(id) on delete set null;

-- Backfill de filas existentes (mismo criterio código-primero-si-existe,
-- si-no nombre que usaba el frontend hasta ahora). Filas sin match
-- quedan con product_id null, igual que ya toleraba el código anterior.
update traza.purchase_order_items i
set product_id = coalesce(
  (select p.id from traza.products p where i.code is not null and p.code = i.code limit 1),
  (select p.id from traza.products p where i.product_name is not null and upper(trim(p.name)) = upper(trim(i.product_name)) limit 1)
)
where i.product_id is null;

update traza.logistics_order_items i
set product_id = (select p.id from traza.products p where i.description is not null and upper(trim(p.name)) = upper(trim(i.description)) limit 1)
where i.product_id is null;

-- Costo unitario del producto al momento de pedirlo en la Orden Logística
-- (copiado de products.cost, editable) — permite cargar el costo de los
-- materiales despachados a la Orden de Trabajo vinculada (work_order_number
-- en logistics_orders), sin depender de que el costo del producto no
-- cambie después.
alter table traza.logistics_order_items add column if not exists unit_cost numeric default 0;
update traza.logistics_order_items i
set unit_cost = coalesce((select p.cost from traza.products p where p.id = i.product_id), 0)
where i.unit_cost is null or i.unit_cost = 0;

-- Enlace opcional a un trabajo específico de la OT ya vinculada en la
-- cabecera (logistics_orders.work_order_number), para que el costo de este
-- ítem se sume a la columna "Piezas" de ese trabajo puntual y no solo al
-- total general de la OT.
alter table traza.logistics_order_items add column if not exists work_order_item_id uuid references traza.work_order_items(id) on delete set null;

-- ---------------------------------------------------------------------
-- Comprobantes de Pago: un comprobante puede cubrir una o varias
-- Órdenes de Compra del mismo proveedor (tabla puente).
-- ---------------------------------------------------------------------
create table if not exists traza.payment_vouchers (
  id uuid primary key default gen_random_uuid(),
  voucher_type text,
  payment_method text,
  credit_days int,
  currency text,
  voucher_series text,
  voucher_number text,
  guide_series text,
  guide_number text,
  issue_date date,
  due_date date,
  created_at timestamptz default now()
);

create table if not exists traza.payment_voucher_orders (
  id uuid primary key default gen_random_uuid(),
  payment_voucher_id uuid not null references traza.payment_vouchers(id) on delete cascade,
  purchase_order_id uuid not null references traza.purchase_orders(id) on delete cascade
);

-- fetchAllRows() en el front ordena SIEMPRE por created_at al cargar
-- cualquier tabla; esta tabla nunca la tuvo, lo que hacía fallar su carga
-- en silencio (error 42703) en cada login y en cada refresh de Realtime.
alter table traza.payment_voucher_orders add column if not exists created_at timestamptz default now();

-- ---------------------------------------------------------------------
-- 2.1 CATÁLOGOS (listas desplegables administrables desde la app)
-- ---------------------------------------------------------------------
create table if not exists traza.catalogs (
  id uuid primary key default gen_random_uuid(),
  category text not null check (category in ('tipo','marca','modelo','carroceria','formula_rodante','ruedas','ejes','sede','servicio','operacion','ciudad','proveedor_combustible','trabajo_correctivo','sistema_ot','personal','componente','comprobante_pago','autorizador','unidad_medida','centro_costo','area_logistica')),
  value text not null,
  created_at timestamptz default now(),
  unique(category, value)
);
alter table traza.catalogs drop constraint if exists catalogs_category_check;
alter table traza.catalogs add constraint catalogs_category_check check (category in ('tipo','marca','modelo','carroceria','formula_rodante','ruedas','ejes','sede','servicio','operacion','ciudad','proveedor_combustible','trabajo_correctivo','sistema_ot','personal','componente','comprobante_pago','autorizador','unidad_medida','centro_costo','area_logistica'));

insert into traza.catalogs (category, value) values
  ('tipo','BUS'),('tipo','MINIBUS'),('tipo','CAMION FURGON'),('tipo','TRACTO'),('tipo','CAMIONETA'),('tipo','MONTACARGA'),('tipo','TRIMOTO'),
  ('marca','SCANIA'),('marca','VOLVO'),('marca','MERCEDES BENZ'),('marca','FREIGHTLINER'),('marca','MAN'),('marca','HYUNDAI'),('marca','KIA'),('marca','TOYOTA'),('marca','CLARK'),('marca','GREAT WALL'),
  ('modelo','K400'),('modelo','K410'),('modelo','K440'),('modelo','K450'),('modelo','B430R'),('modelo','B450R'),('modelo','O500RSD'),('modelo','LO 916/48'),('modelo','ATEGO 2428'),('modelo','ATEGO 1726'),('modelo','ACCELO 1016'),('modelo','ATEGO 1419'),('modelo','P320'),('modelo','M2'),('modelo','CL120'),('modelo','H-100 TRUCK'),
  ('carroceria','MARCOPOLO'),('carroceria','COMIL'),('carroceria','MODASA'),('carroceria','METALVAL'),('carroceria','BRUCE'),('carroceria','CONTIBUS'),('carroceria','HALCON'),
  ('formula_rodante','4X2'),('formula_rodante','4X4'),('formula_rodante','6X2'),('formula_rodante','6X4'),('formula_rodante','8X2'),('formula_rodante','6X2X4'),
  ('ruedas','6'),('ruedas','8'),('ruedas','10'),('ruedas','12'),
  ('ejes','2'),('ejes','3'),('ejes','4'),
  ('sede','INTERPROVINCIAL'),('sede','LIMA'),('sede','CAJAMARCA'),('sede','TRUJILLO'),('sede','CHICLAYO'),('sede','JAEN'),('sede','PIURA'),
  ('servicio','ORO'),('servicio','PLATA'),('servicio','CLASICO'),('servicio','NO CORRESPONDE'),
  ('operacion','INTERPROVINCIAL'),('operacion','PERSONAL'),('operacion','TURISTICO'),('operacion','CARGA'),('operacion','LOCAL'),
  ('ciudad','LIMA'),('ciudad','TRUJILLO'),('ciudad','CAJAMARCA'),('ciudad','JAEN'),('ciudad','CHICLAYO'),('ciudad','PIURA'),
  ('proveedor_combustible','PRIMAX'),('proveedor_combustible','REPSOL'),('proveedor_combustible','PETROPERU'),('proveedor_combustible','PECSA'),('proveedor_combustible','GRIFO INDEPENDIENTE'),
  ('trabajo_correctivo','REPARACION DE SISTEMA ELECTRICO'),('trabajo_correctivo','CAMBIO DE EMBRAGUE'),('trabajo_correctivo','REPARACION DE MOTOR'),('trabajo_correctivo','CAMBIO DE BATERIA'),('trabajo_correctivo','REPARACION DE SISTEMA DE FRENOS'),('trabajo_correctivo','SOLDADURA DE CHASIS'),('trabajo_correctivo','CAMBIO DE AMORTIGUADORES'),('trabajo_correctivo','REPARACION DE SUSPENSION'),
  ('sistema_ot','AIRE'),('sistema_ot','AIRE ACONDICIONADO'),('sistema_ot','CARROCERIA'),('sistema_ot','CORONA'),('sistema_ot','DIRECCION'),('sistema_ot','ELECTRICO'),('sistema_ot','EMBRAGUE'),('sistema_ot','FRENOS'),('sistema_ot','MOTOR'),('sistema_ot','PINTURA'),('sistema_ot','REFRIGERACION'),('sistema_ot','RETARDER'),('sistema_ot','RUEDAS'),('sistema_ot','SUSPENSION'),('sistema_ot','TRANSMISION'),('sistema_ot','NEUMATICOS'),
  ('componente','MOTOR'),('componente','CAJA DE CAMBIOS'),('componente','DIFERENCIAL'),('componente','SISTEMA DE FRENOS'),('componente','NEUMATICOS'),('componente','BATERIA'),('componente','ALTERNADOR'),('componente','RADIADOR'),('componente','EMBRAGUE'),('componente','SUSPENSION'),
  ('comprobante_pago','FACTURA'),('comprobante_pago','BOLETA'),('comprobante_pago','RECIBO POR HONORARIOS'),('comprobante_pago','TICKET'),
  ('unidad_medida','UNIDAD'),('unidad_medida','GALON'),('unidad_medida','LITRO'),('unidad_medida','KILOGRAMO'),('unidad_medida','METRO'),('unidad_medida','JUEGO'),('unidad_medida','PAR'),('unidad_medida','CAJA'),
  ('area_logistica','MANTENIMIENTO'),('area_logistica','FLOTA'),('area_logistica','ADMINISTRACION'),('area_logistica','LIMPIEZA')
on conflict (category, value) do nothing;

-- ---------------------------------------------------------------------
-- LIMPIEZA: normalizar catálogos ya guardados con mayúscula/minúscula
-- mezclada (ej. "Bus" en vez de "BUS") — esto es lo que hacía que los
-- desplegables mostraran valores repetidos con distinta capitalización.
-- Pasa TODO a mayúscula sin tildes, y si dos filas quedan idénticas tras
-- normalizar, se queda con la más antigua y borra el resto. Seguro de
-- re-correr (converge al mismo resultado siempre).
with normalized as (
  select id, category,
    translate(upper(value), 'ÁÉÍÓÚÜ', 'AEIOUU') as norm_value
  from traza.catalogs
),
ranked as (
  select id, category, norm_value,
    row_number() over (partition by category, norm_value order by id) as rn
  from normalized
)
delete from traza.catalogs c using ranked r
where c.id = r.id and r.rn > 1;

update traza.catalogs
set value = translate(upper(value), 'ÁÉÍÓÚÜ', 'AEIOUU')
where value <> translate(upper(value), 'ÁÉÍÓÚÜ', 'AEIOUU');

-- ---------------------------------------------------------------------
-- 3. ROW LEVEL SECURITY
-- Todos los roles autenticados pueden LEER (incluye Solo lectura).
-- Solo Admin y Operaciones pueden CREAR/EDITAR/BORRAR.
-- La tabla profiles solo la administra Admin (salvo leer su propia fila).
-- ---------------------------------------------------------------------
alter table traza.profiles enable row level security;
alter table traza.vehicles enable row level security;
alter table traza.drivers enable row level security;
alter table traza.maintenance enable row level security;
alter table traza.fuel_logs enable row level security;
alter table traza.tires enable row level security;
alter table traza.routes enable row level security;
alter table traza.checklists enable row level security;
alter table traza.inventory enable row level security;
alter table traza.purchase_orders enable row level security;
alter table traza.catalogs enable row level security;
alter table traza.vehicle_km_logs enable row level security;
alter table traza.tire_events enable row level security;
alter table traza.tire_inspections enable row level security;

-- Estas tablas ya tenían políticas de acceso creadas más abajo (loop de
-- políticas genéricas), pero nunca se les activó RLS explícitamente — por
-- eso Supabase las marcaba como "Table publicly accessible" (RLS
-- disabled): sin este ALTER, las políticas existen pero no se aplican, y
-- la tabla queda abierta a cualquiera con la URL del proyecto.
alter table traza.maintenance_cycles enable row level security;
alter table traza.maintenance_cycle_tasks enable row level security;
alter table traza.maintenance_cycle_parts enable row level security;
alter table traza.work_orders enable row level security;
alter table traza.work_order_items enable row level security;
alter table traza.purchase_order_items enable row level security;
alter table traza.suppliers enable row level security;
alter table traza.products enable row level security;
alter table traza.logistics_orders enable row level security;
alter table traza.logistics_order_items enable row level security;
alter table traza.payment_vouchers enable row level security;
alter table traza.payment_voucher_orders enable row level security;
alter table traza.component_life_config enable row level security;
alter table traza.component_life_overrides enable row level security;
alter table traza.scheduled_maintenance enable row level security;
alter table traza.route_rates enable row level security;
alter table traza.driver_attendance enable row level security;
alter table traza.driver_payroll_config enable row level security;

-- Tablas huérfanas de un diseño anterior (ya no las usa la app actual, pero
-- siguen existiendo en la base con políticas creadas y RLS deshabilitado —
-- reportado por el linter de seguridad de Supabase). Con IF EXISTS por si
-- en algún proyecto nuevo nunca llegaron a crearse.
alter table if exists traza.maintenance_plan_tasks enable row level security;
alter table if exists traza.maintenance_plan_vehicles enable row level security;

-- catalogs: todos leen; solo Admin gestiona las listas
drop policy if exists "catalogs_select_all" on traza.catalogs;
create policy "catalogs_select_all" on traza.catalogs for select using (auth.uid() is not null);
drop policy if exists "catalogs_write_admin" on traza.catalogs;
create policy "catalogs_write_admin" on traza.catalogs for insert with check (traza.is_admin());
drop policy if exists "catalogs_update_admin" on traza.catalogs;
create policy "catalogs_update_admin" on traza.catalogs for update using (traza.is_admin());
drop policy if exists "catalogs_delete_admin" on traza.catalogs;
create policy "catalogs_delete_admin" on traza.catalogs for delete using (traza.is_admin());

-- profiles
drop policy if exists "profiles_select_own_or_admin" on traza.profiles;
create policy "profiles_select_own_or_admin" on traza.profiles for select
  using (auth.uid() = id or traza.is_admin());
drop policy if exists "profiles_update_admin" on traza.profiles;
create policy "profiles_update_admin" on traza.profiles for update
  using (traza.is_admin());

-- plantilla reutilizada para cada tabla operativa
do $$
declare
  t text;
begin
  foreach t in array array['vehicles','drivers','maintenance','fuel_logs','tires','tire_events','tire_inspections','routes','checklists','inventory','purchase_orders','maintenance_cycles','maintenance_cycle_tasks','work_orders','work_order_items','purchase_order_items','suppliers','products','services','logistics_orders','logistics_order_items','payment_vouchers','payment_voucher_orders','component_life_config','component_life_overrides','maintenance_cycle_parts','scheduled_maintenance','route_rates','driver_attendance','driver_payroll_config','vehicle_km_logs']
  loop
    execute format('drop policy if exists "%1$s_select_all" on traza.%1$s;', t);
    execute format('create policy "%1$s_select_all" on traza.%1$s for select using (auth.uid() is not null);', t);
    execute format('drop policy if exists "%1$s_write_roles" on traza.%1$s;', t);
    execute format('create policy "%1$s_write_roles" on traza.%1$s for insert with check (traza.can_write());', t);
    execute format('drop policy if exists "%1$s_update_roles" on traza.%1$s;', t);
    execute format('create policy "%1$s_update_roles" on traza.%1$s for update using (traza.can_write());', t);
    execute format('drop policy if exists "%1$s_delete_roles" on traza.%1$s;', t);
    execute format('create policy "%1$s_delete_roles" on traza.%1$s for delete using (traza.can_write());', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 3b. REPORTES DE FALLA (rol Conductor) — "pre-OT" que el chofer manda
-- desde su celular, en ruta o al llegar a un terminal. No usa la plantilla
-- genérica de arriba porque sus reglas son distintas: un Conductor puede
-- crear y ver SOLO lo suyo; el staff (can_write) ve y triagea todo. Desde
-- Mantenimiento, el staff puede generar una Orden de Trabajo real a partir
-- de un reporte (ver work_order_id) — igual que ya existe para Checklist.
-- ---------------------------------------------------------------------
create table if not exists traza.fault_reports (
  id uuid primary key default gen_random_uuid(),
  plate text not null,
  driver_id uuid references traza.drivers(id) on delete set null,
  driver_name text,
  location_type text check (location_type in ('Ruta','Terminal')),
  place text,
  km numeric,
  system text,
  description text not null,
  priority text not null default 'Normal' check (priority in ('Normal','Alta','Urgente')),
  status text not null default 'Pendiente' check (status in ('Pendiente','Convertido a OT','Descartado')),
  work_order_id uuid references traza.work_orders(id) on delete set null,
  created_by uuid references auth.users(id) default auth.uid(),
  created_at timestamptz default now()
);
alter table traza.fault_reports enable row level security;

-- Rediseño: un solo login "conductor" compartido entre todos los pilotos
-- (no una cuenta por piloto — evita depender de la Edge Function create-user
-- para dar de alta a cada uno). El piloto elige su propio nombre en el
-- formulario en vez de depender de profiles.driver_id, "Lugar" pasa a ser
-- un solo campo libre (ya no Ruta/Terminal), las averías se agrupan en 3
-- campos por especialidad (mecánica/eléctrica/carrocería, cada uno admite
-- varios trabajos en líneas separadas) y se quita el campo Prioridad.
alter table traza.fault_reports drop constraint if exists fault_reports_location_type_check;
alter table traza.fault_reports drop column if exists location_type;
alter table traza.fault_reports drop column if exists system;
alter table traza.fault_reports drop column if exists description;
alter table traza.fault_reports drop constraint if exists fault_reports_priority_check;
alter table traza.fault_reports drop column if exists priority;
alter table traza.fault_reports add column if not exists mechanical_issues text;
alter table traza.fault_reports add column if not exists electrical_issues text;
alter table traza.fault_reports add column if not exists bodywork_issues text;
alter table traza.profiles drop column if exists driver_id;

drop policy if exists "fault_reports_select" on traza.fault_reports;
create policy "fault_reports_select" on traza.fault_reports for select
  using (not traza.is_conductor() or created_by = auth.uid());

drop policy if exists "fault_reports_insert" on traza.fault_reports;
create policy "fault_reports_insert" on traza.fault_reports for insert
  with check (traza.can_write() or traza.is_conductor());

-- Solo el staff triagea (cambia estado, lo vincula a una OT) — un Conductor
-- no puede editar un reporte una vez enviado.
drop policy if exists "fault_reports_update" on traza.fault_reports;
create policy "fault_reports_update" on traza.fault_reports for update
  using (traza.can_write());

drop policy if exists "fault_reports_delete" on traza.fault_reports;
create policy "fault_reports_delete" on traza.fault_reports for delete
  using (traza.is_admin());

-- ---------------------------------------------------------------------
-- 4. Asegurar permisos sobre las tablas y funciones ya creadas
-- (el ALTER DEFAULT PRIVILEGES del inicio solo cubre objetos futuros;
-- esto cubre las tablas/funciones que este mismo script acaba de crear)
-- ---------------------------------------------------------------------
grant all on all tables in schema traza to anon, authenticated, service_role;
grant execute on all functions in schema traza to anon, authenticated, service_role;
grant usage, select on all sequences in schema traza to anon, authenticated, service_role;
alter default privileges for role postgres in schema traza grant usage, select on sequences to anon, authenticated, service_role;

-- ---------------------------------------------------------------------
-- 5. VISTA CALCULADA: Km Recorridos y KPG de combustible
--
-- En vez de guardar km_reco/kpg como valores fijos (que se podían
-- desactualizar con cargas fuera de orden, duplicados, etc.), esta vista
-- los calcula siempre al vuelo con el método "full-to-full":
--   - Para cada tanqueo marcado como Full, busca el Full anterior más
--     cercano de la misma placa.
--   - Km Reco = km actual - km de ese Full anterior.
--   - KPG = Km Reco / (galones del tanqueo actual + galones de todos los
--     tanqueos NO-full que hubo entre medio).
-- La app lee de esta vista para mostrar los datos; los registros se
-- siguen guardando/editando en traza.fuel_logs como siempre.
-- ---------------------------------------------------------------------
create or replace view traza.fuel_logs_computed
with (security_invoker = true)
as
with ordered as (
  select
    f.*,
    sum(case when f.is_full_tank then 1 else 0 end) over (
      partition by f.plate
      order by f.date, nullif(f.time,'')::time nulls first, f.created_at
      rows between unbounded preceding and current row
    ) as full_group
  from traza.fuel_logs f
),
group_totals as (
  select plate, full_group, sum(gallons) as group_gallons
  from ordered
  group by plate, full_group
),
full_rows as (
  select plate, full_group, odometer as full_odometer, gallons as full_gallons
  from ordered
  where is_full_tank
)
select
  o.id, o.plate, o.voucher_number, o.date, o.time, o.odometer, o.route,
  o.pilot_id, o.copilot_id, o.gallons, o.ppg, o.is_full_tank, o.city, o.supplier,
  o.cost, o.created_at,
  case
    when o.is_full_tank and pf.full_odometer is not null
    then o.odometer - pf.full_odometer
    else null
  end as km_reco,
  case
    when o.is_full_tank and pf.full_odometer is not null
         and (o.gallons + coalesce(gt.group_gallons,0) - coalesce(pf.full_gallons,0)) > 0
    then round( (o.odometer - pf.full_odometer)::numeric / (o.gallons + coalesce(gt.group_gallons,0) - coalesce(pf.full_gallons,0)), 2)
    else null
  end as kpg,
  o.destination, o.observations
from ordered o
left join full_rows pf on pf.plate = o.plate and pf.full_group = o.full_group - 1
left join group_totals gt on gt.plate = o.plate and gt.full_group = o.full_group - 1;

grant select on traza.fuel_logs_computed to anon, authenticated, service_role;

-- ---------------------------------------------------------------------
-- REALTIME: agrega las tablas del schema traza a la publicación
-- supabase_realtime, para que los cambios se propaguen solos entre
-- computadoras (ver setupRealtimeSync() en traza-erp.html). Alternativa
-- por SQL a hacerlo a mano en Database > Replication. Idempotente: si
-- una tabla ya está en la publicación, la salta sin error.
do $$
declare t text;
begin
  foreach t in array array[
    'vehicles','drivers','maintenance','fuel_logs','tires','tire_events','tire_inspections','routes','checklists','inventory',
    'purchase_orders','purchase_order_items','maintenance_cycles','maintenance_cycle_tasks','maintenance_cycle_parts',
    'work_orders','work_order_items','suppliers','products','services',
    'logistics_orders','logistics_order_items','payment_vouchers','payment_voucher_orders',
    'component_life_config','component_life_overrides','scheduled_maintenance',
    'route_rates','driver_attendance','driver_payroll_config','vehicle_km_logs','fault_reports'
  ]
  loop
    if not exists (
      select 1 from pg_publication_tables
      where pubname='supabase_realtime' and schemaname='traza' and tablename=t
    ) then
      execute format('alter publication supabase_realtime add table traza.%I', t);
    end if;
  end loop;
end $$;

-- =====================================================================
-- Fin del script. Sigue con SETUP.md: falta exponer el schema "traza"
-- en Project Settings > API antes de que la app pueda usarlo.
-- =====================================================================
