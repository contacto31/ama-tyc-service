// db.js
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.warn('[DB] DATABASE_URL no está definida en las variables de entorno.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // En tu VPS los servicios están en la misma red interna, no necesitamos SSL.
  // Si algún día cambias a un proveedor que exija SSL, aquí lo ajustamos.
  ssl: false,
});

// Pequeña prueba de conexión al arrancar (solo loguea, no rompe la app)
pool
  .connect()
  .then(client => {
    return client
      .query('SELECT NOW() as now')
      .then(res => {
        console.log('[DB] Conectado a Postgres. Hora del servidor:', res.rows[0].now);
        client.release();
      })
      .catch(err => {
        client.release();
        console.error('[DB] Error probando la conexión a Postgres:', err.message);
      });
  })
  .catch(err => {
    console.error('[DB] No se pudo conectar a Postgres:', err.message);
  });

module.exports = {
  pool,
};
