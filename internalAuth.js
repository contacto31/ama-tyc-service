// internalAuth.js
require('dotenv').config();

/**
 * Middleware para proteger endpoints internos (llamados solo por n8n u otros servicios de confianza)
 * Valida el header: X-Internal-Secret
 * Contra la variable de entorno: INTERNAL_API_SECRET
 */
function requireInternalSecret(req, res, next) {
  const configuredSecret = process.env.INTERNAL_API_SECRET;

  if (!configuredSecret) {
    console.error('❌ INTERNAL_API_SECRET no está configurada en las variables de entorno.');
    return res.status(500).json({
      ok: false,
      error: 'INTERNAL_API_SECRET no está configurada en el servidor'
    });
  }

  const incoming = req.headers['x-internal-secret'];

  if (!incoming || incoming !== configuredSecret) {
    console.warn('⚠️ Intento de acceso no autorizado a endpoint interno.');
    return res.status(401).json({
      ok: false,
      error: 'No autorizado'
    });
  }

  // Autorizado
  return next();
}

module.exports = {
  requireInternalSecret
};
