require('dotenv').config(); // Solo necesario para desarrollo local
const mysql = require('mysql2/promise'); // Usamos la versión con promesas

// Configuración dinámica para Railway o local
const dbConfig = {
  host: process.env.MYSQLHOST || process.env.DB_HOST || 'localhost',
  port: process.env.MYSQLPORT || process.env.DB_PORT,
  user: process.env.MYSQLUSER || process.env.DB_USER || 'root',
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.MYSQLDATABASE || process.env.DB_NAME || 'railway',
  ssl: process.env.NODE_ENV === 'production' ? { 
    rejectUnauthorized: false // Obligatorio para Railway
  } : null,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Creamos un pool de conexiones (mejor que conexión única)
const pool = mysql.createPool(dbConfig);

// Verificación de conexión al iniciar
(async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Conectado a MySQL en:', dbConfig.host);
    console.log(`📦 Base de datos: ${dbConfig.database}`);
    connection.release();
  } catch (err) {
    console.error('❌ Error de conexión a MySQL:', {
      code: err.code,
      message: err.message,
      config: {
        host: dbConfig.host,
        port: dbConfig.port,
        database: dbConfig.database
      }
    });
    process.exit(1); // Termina la aplicación si no hay conexión
  }
})();

// Manejo de errores del pool
pool.on('error', (err) => {
  console.error('🚨 Error en el pool de MySQL:', err.message);
});

module.exports = {
  query: (sql, params) => pool.query(sql, params),
  getConnection: () => pool.getConnection(),
  pool: pool // Para acceso directo si lo necesitas
};