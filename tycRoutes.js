// tycRoutes.js
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const { pool } = require('./db');
const { requireInternalSecret } = require('./internalAuth');

const router = express.Router();

/**
 * "Mini-DB" en memoria
 * Key: token
 * Value: objeto con datos de la solicitud TyC
 */
const solicitudesTyC = new Map();

// Estados posibles
const STATES = {
  CREADA: 'CREADA',
  ABIERTA: 'ABIERTA',
  ACEPTADA: 'ACEPTADA',
  EXPIRADA: 'EXPIRADA'
};

/**
 * Helper para obtener fecha ISO actual
 */
function nowIso() {
  return new Date().toISOString();
}

/**
 * Envía un webhook a n8n cuando cambia el estado de la solicitud.
 * Usa webhookUrl que llegó en la creación de la solicitud.
 * Firma el payload con WEBHOOK_SECRET usando HMAC-SHA256.
 */
async function sendWebhook(solicitud, evento) {
  const webhookUrl = solicitud.webhookUrl;
  if (!webhookUrl) {
    console.warn('⚠️ No hay webhookUrl configurado en la solicitud, no se envía nada.');
    return;
  }

  const payload = {
    evento,                              // "TYC_ACEPTADA" o "TYC_EXPIRADA"
    preclienteId: solicitud.preclienteId,
    tycSolicitudId: solicitud.tycSolicitudId,
    estado: solicitud.estado,
    createdAt: solicitud.createdAt,
    expiresAt: solicitud.expiresAt,
    openedAt: solicitud.openedAt || null,
    acceptedAt: solicitud.acceptedAt || null
  };

  const secret = process.env.WEBHOOK_SECRET || 'default_secret';
  const bodyStr = JSON.stringify(payload);
  const signature = crypto
    .createHmac('sha256', secret)
    .update(bodyStr)
    .digest('hex');

  try {
    await axios.post(webhookUrl, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-AMA-Signature': signature,
        'X-AMA-Event': evento
      },
      timeout: 5000
    });

    console.log(`🔔 Webhook enviado a n8n (${evento}) para preclienteId=${solicitud.preclienteId}`);
  } catch (err) {
    console.error('❌ Error enviando webhook TyC:', err.message);
  }
}

/**
 * POST /api/tyc/solicitudes
 *
 * Lo va a llamar n8n.
 * Recibe:
 *  - preclienteId (string, obligatorio)
 *  - canal (string, opcional, default "WHATSAPP")
 *  - ttlMinutos (number, opcional, default 60)
 *  - webhookUrl (string, obligatorio)
 *  - metadata (objeto, opcional)
 *
 * Responde:
 *  - ok: true/false
 *  - tycSolicitudId
 *  - preclienteId
 *  - url (para mandarle al usuario por WhatsApp)
 *  - token
 *  - expiresAt
 */
router.post('/api/tyc/solicitudes', async (req, res) => {
  try {
    const { preclienteId, canal, ttlMinutos, webhookUrl, metadata } = req.body || {};

    // Validaciones básicas
    if (!preclienteId) {
      return res.status(400).json({
        ok: false,
        error: 'preclienteId es obligatorio'
      });
    }

    if (!webhookUrl) {
      return res.status(400).json({
        ok: false,
        error: 'webhookUrl es obligatorio (a dónde avisaremos a n8n)'
      });
    }

    // TTL (tiempo de vida) en minutos; default 60
    const ttl = typeof ttlMinutos === 'number' && ttlMinutos > 0 ? ttlMinutos : 60;

    const ahora = new Date();
    const expiresAt = new Date(ahora.getTime() + ttl * 60 * 1000);

    // Generamos un token aleatorio seguro
    const token = crypto.randomBytes(16).toString('hex');
    
    // Hash del token para guardar en BD (token_hash)
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Generamos un ID de solicitud (simple por ahora)
    const tycSolicitudId = `TYC-${Date.now()}`;

    // Creamos el objeto de solicitud (lo que vamos a guardar en memoria y usar para responder)
    const solicitud = {
      tycSolicitudId,
      preclienteId,
      canal: canal || 'WHATSAPP',
      token,
      estado: STATES.CREADA,
      createdAt: ahora.toISOString(),
      expiresAt: expiresAt.toISOString(),
      webhookUrl,
      metadata: metadata || {},
      acceptedAt: null,
      acceptedIp: null,
      acceptedUserAgent: null
    };

    // Guardar en BD (tabla tyc_solicitudes)
    try {
      await pool.query(
  `INSERT INTO tyc_solicitudes (
    tyc_solicitud_id,
    precliente_id,
    token,
    token_hash,
    canal,
    webhook_url,
    metadata,
    estado,
    created_at,
    expires_at
  ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
  [
    solicitud.tycSolicitudId,
    solicitud.preclienteId,
    solicitud.token,
    tokenHash,
    solicitud.canal,
    solicitud.webhookUrl,
    solicitud.metadata,
    solicitud.estado,
    solicitud.createdAt,
    solicitud.expiresAt
  ]
);
    } catch (err) {
      console.error('[TyC] Error guardando solicitud en BD:', err);
      return res.status(500).json({
        ok: false,
        error: 'Error guardando la solicitud de TyC en la base de datos'
      });
    }

    // Guardamos en la "mini-DB" en memoria (para compatibilidad con lo que ya está hecho)
    solicitudesTyC.set(token, solicitud);

    // Construimos la URL base desde ENV o default en local
    const baseUrl = process.env.TYC_BASE_URL || `http://localhost:${process.env.PORT || 3002}`;
    const url = `${baseUrl}/tyc/${token}`;

    // Respondemos a n8n
    return res.json({
      ok: true,
      tycSolicitudId,
      preclienteId,
      url,
      token,
      expiresAt: solicitud.expiresAt
    });
  } catch (err) {
    console.error('[TyC] Error inesperado en /api/tyc/solicitudes:', err);
    return res.status(500).json({
      ok: false,
      error: 'Error inesperado creando la solicitud de TyC'
    });
  }
});


/**
 * GET /tyc/:token
 *
 * Muestra la página HTML con los Términos y Condiciones.
 * - Valida que el token exista en nuestra "mini-DB".
 * - Revisa si ya expiró.
 * - Si es la primera vez que se abre, cambia estado de CREADA -> ABIERTA.
 * - Renderiza un HTML con:
 *    - ID de precliente
 *    - Fecha de expiración
 *    - Caja scrollable con el texto del contrato
 *    - Botón de "Aceptar" que se habilita solo al llegar al final del texto
 */
router.get('/tyc/:token', async (req, res) => {
  const { token } = req.params;

  // 1) Intentamos primero en memoria
  let solicitud = solicitudesTyC.get(token);

  // 2) Si no está en memoria (reinicio / scale), la traemos de BD
  if (!solicitud) {
    try {
      const r = await pool.query(
        `SELECT
          tyc_solicitud_id,
          precliente_id,
          token,
          canal,
          webhook_url,
          metadata,
          estado,
          created_at,
          expires_at,
          opened_at,
          accepted_at,
          accepted_ip
        FROM tyc_solicitudes
        WHERE token = $1
        LIMIT 1`,
        [token]
      );

      if (r.rowCount === 0) {
        return res
          .status(404)
          .send('<h1>Enlace inválido</h1><p>Esta URL no existe o ya no es válida.</p>');
      }

      const row = r.rows[0];

      // Re-hidratamos al mismo formato que usas en memoria
      solicitud = {
        tycSolicitudId: row.tyc_solicitud_id,
        preclienteId: row.precliente_id,
        canal: row.canal,
        token: row.token,
        estado: row.estado,
        createdAt: row.created_at?.toISOString?.() ?? String(row.created_at),
        expiresAt: row.expires_at?.toISOString?.() ?? String(row.expires_at),
        webhookUrl: row.webhook_url,
        metadata: row.metadata || {},
        openedAt: row.opened_at ? (row.opened_at.toISOString?.() ?? String(row.opened_at)) : null,
        acceptedAt: row.accepted_at ? (row.accepted_at.toISOString?.() ?? String(row.accepted_at)) : null,
        acceptedIp: row.accepted_ip || null,
      };

      // Guardamos en memoria para que lo demás siga igual
      solicitudesTyC.set(token, solicitud);
    } catch (err) {
      console.error('[TyC] Error consultando BD en GET /tyc/:token:', err);
      return res.status(500).send('<h1>Error</h1><p>Error interno.</p>');
    }
  }

  const ahora = new Date();
  const expira = new Date(solicitud.expiresAt);

  // Verificar expiración
  if (expira < ahora && solicitud.estado !== STATES.ACEPTADA) {
    const yaEstabaExpirada = (solicitud.estado === STATES.EXPIRADA);

    // Solo si NO estaba expirada, cambiamos estado y avisamos a n8n
    if (!yaEstabaExpirada) {
      solicitud.estado = STATES.EXPIRADA;
      solicitudesTyC.set(token, solicitud);

      // Persistimos estado EXPIRADA en BD
      try {
        await pool.query(
          `UPDATE tyc_solicitudes
           SET estado = $2
           WHERE token = $1`,
          [token, STATES.EXPIRADA]
        );
      } catch (err) {
        console.error('[TyC] Error actualizando estado EXPIRADA en BD:', err);
      }

      // Avisamos a n8n que esta solicitud expiró
      sendWebhook(solicitud, 'TYC_EXPIRADA').catch((err) => {
        console.error('Error en webhook TYC_EXPIRADA (GET /tyc):', err.message);
      });
    }

    return res
      .status(410)
      .send('<h1>Enlace expirado</h1><p>Esta URL ya no está disponible. Solicita una nueva.</p>');
  }

  // Si estaba CREADA, la marcamos como ABIERTA y registramos openedAt (memoria)
  if (solicitud.estado === STATES.CREADA) {
    solicitud.estado = STATES.ABIERTA;
    solicitud.openedAt = nowIso();
    solicitudesTyC.set(token, solicitud);
  }

  // Persistimos opened_at (solo si es null) y el cambio de estado a ABIERTA (solo si era CREADA)
  try {
    await pool.query(
      `UPDATE tyc_solicitudes
       SET
         opened_at = COALESCE(opened_at, NOW()),
         estado = CASE WHEN estado = $2 THEN $3 ELSE estado END
       WHERE token = $1`,
      [token, STATES.CREADA, STATES.ABIERTA]
    );
  } catch (err) {
    console.error('[TyC] Error actualizando opened_at/estado en BD:', err);
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  const fechaExpiraStr = new Intl.DateTimeFormat('es-MX', {
    timeZone: 'America/Mexico_City',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  }).format(expira);

  const html = `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Términos y Condiciones AMA Track & Safe</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background-color: #f5f5f5;
      margin: 0;
      padding: 0;
      display: flex;
      justify-content: center;
    }
    .container {
      max-width: 800px;
      width: 100%;
      background-color: #ffffff;
      margin: 24px;
      padding: 24px;
      border-radius: 12px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.08);
    }
    h1 {
      font-size: 22px;
      margin-bottom: 8px;
    }
    .subtitle {
      font-size: 14px;
      color: #666;
      margin-bottom: 16px;
    }
    .tyc-box {
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 16px;
      height: 320px;
      overflow-y: auto;
      background-color: #fafafa;
      margin-bottom: 16px;
    }
    .status-info {
      font-size: 13px;
      color: #999;
      margin-bottom: 12px;
    }
    button {
      width: 100%;
      padding: 12px 16px;
      font-size: 16px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      font-weight: 600;
    }
    button:disabled {
      background-color: #ccc;
      color: #666;
      cursor: not-allowed;
    }
    .btn-primary {
      background-color: #E27C39;
      color: #fff;
    }

    .btn-secondary {
      background-color: #3C3C3C;
      color: #fff;
    }
    .btn-accepted {
      background-color: #16a34a !important;
      color: #fff !important;
      cursor: not-allowed !important;
      opacity: 0.98;
    }
    .actions {
      display: flex;
      gap: 10px;
      margin-top: 10px;
      margin-bottom: 14px;
    }
    .actions .btn-secondary {
      width: 50%;
      padding: 10px 12px;
      font-size: 14px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      font-weight: 600;
    }
    .footer-text {
      font-size: 11px;
      color: #999;
      margin-top: 8px;
      text-align: center;
    }
    .msg {
      font-size: 12px;
      color: #555;
      margin-top: 8px;
      text-align: center;
      min-height: 1.2em;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Contrato de Servicio AMA Track & Safe</h1>
    <div class="subtitle">
      Por favor revisa cuidadosamente los términos y condiciones del servicio antes de continuar.
    </div>

    <div class="status-info">
      ID de precliente: <strong>${solicitud.preclienteId}</strong><br/>
      Esta liga expira el: <strong>${fechaExpiraStr}</strong>
    </div>

    <div id="tycBox" class="tyc-box">
      <!-- Aquí va el texto completo de tu contrato -->
      <p><strong>1. Objeto del servicio</strong><br/>
      AMA Track & Safe ofrece un servicio de localización y corte de corriente del vehículo del contratante por medio de un dispositivo GPS y un agente digital de atención. El objetivo es brindar mayor tranquilidad al usuario y su familia al contar con soporte para situaciones de riesgo o siniestro.</p>

      <p><strong>2. Alcance y limitaciones</strong><br/>
      El servicio se limita a la operación remota del dispositivo instalado en el vehículo y a la gestión de eventos reportados por el contratante o su contacto autorizado. AMA Track & Safe no se hace responsable por fallas mecánicas o eléctricas del vehículo, anteriores o posteriores a la instalación del dispositivo.</p>

      <p><strong>3. Costos del servicio</strong><br/>
      El servicio contempla un costo de instalación y un costo mensual de suscripción. Los montos, forma de pago y consecuencias por falta de pago se especifican en el contrato que se comparte al usuario como parte de este documento.</p>

      <p><strong>4. Mecánica de atención de siniestros</strong><br/>
      Para la atención de siniestros se podrá solicitar el NIP de seguridad y la validación de la identidad del contratante. AMA Track & Safe ejecutará las acciones razonables dentro de su alcance tecnológico y operativo, sin garantizar la recuperación del vehículo.</p>

      <p><strong>5. Tratamiento de datos personales</strong><br/>
      Los datos del contratante, del vehículo y de geolocalización se utilizarán exclusivamente para la prestación del servicio y para el cumplimiento de obligaciones legales. El detalle del aviso de privacidad forma parte integral de estos términos.</p>

            <p>Al aceptar estos términos y condiciones, reconoces que has leído, entendido y aceptado el contenido.</p>
    </div>

    <div id="msg" class="msg"></div>

    <div class="actions">
      <button id="btnDescargar" class="btn-secondary" type="button">Descargar TyC</button>
      <button id="btnImprimir" class="btn-secondary" type="button">Imprimir</button>
    </div>

    <button id="btnAceptar" class="btn-primary" type="button" disabled>Acepto términos y condiciones</button>

    <script>
      // El backend inyecta aquí el token actual
      const TOKEN = "${token}";
      const ALREADY_ACCEPTED = ${solicitud.estado === STATES.ACEPTADA ? 'true' : 'false'};

      const tycBox = document.getElementById('tycBox');
      const btnAceptar = document.getElementById('btnAceptar');
      const btnDescargar = document.getElementById('btnDescargar');
      const btnImprimir = document.getElementById('btnImprimir');
      const msg = document.getElementById('msg');

      let tycAceptados = false;

      function marcarComoAceptadoUI() {
        tycAceptados = true;
        btnAceptar.disabled = true;
        btnAceptar.textContent = 'Términos y condiciones aceptados';
        btnAceptar.classList.add('btn-accepted');
        msg.textContent = '✅ Términos y condiciones aceptados. Puedes regresar a la conversación.';
      }

      function checkScroll() {
        if (tycAceptados) {
          btnAceptar.disabled = true;
          return;
        }
        const scrollTop = tycBox.scrollTop;
        const scrollHeight = tycBox.scrollHeight;
        const clientHeight = tycBox.clientHeight;

        if (scrollTop + clientHeight >= scrollHeight - 5) {
          btnAceptar.disabled = false;
          msg.textContent = 'Ya puedes aceptar los términos y condiciones.';
        } else {
          btnAceptar.disabled = true;
          msg.textContent = 'Desplázate hasta el final para habilitar el botón.';
        }
      }

      // Inicializa estado al cargar
      if (ALREADY_ACCEPTED) {
        marcarComoAceptadoUI();
      } else {
        tycBox.addEventListener('scroll', checkScroll);
        checkScroll();
      }

      btnAceptar.addEventListener('click', async () => {
        if (tycAceptados) return;

        btnAceptar.disabled = true;
        msg.textContent = 'Registrando tu aceptación, por favor espera...';

        try {
          const response = await fetch('/api/tyc/' + encodeURIComponent(TOKEN) + '/aceptar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
          });

          const data = await response.json();

          if (!data.ok) {
            msg.textContent = 'No fue posible registrar tu aceptación: ' + (data.error || 'intenta más tarde.');
            tycAceptados = false;
            checkScroll();
            return;
          }

          marcarComoAceptadoUI();
        } catch (error) {
          console.error(error);
          msg.textContent = 'Ocurrió un error al registrar tu aceptación. Intenta nuevamente.';
          tycAceptados = false;
          checkScroll();
        }
      });

      // Descargar como TXT (simple, sin PDF)
      btnDescargar?.addEventListener('click', () => {
        const contenido = tycBox?.innerText || '';
        const blob = new Blob([contenido], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = 'terminos-y-condiciones-ama-track-safe.txt';
        document.body.appendChild(a);
        a.click();
        a.remove();

        URL.revokeObjectURL(url);
      });

      // Imprimir
      btnImprimir?.addEventListener('click', () => {
        window.print();
      });
    </script>
  </div>
</body>
</html>
`;

  return res.send(html);
});

/**
 * POST /api/tyc/:token/aceptar
 *
 * Lo llama el frontend cuando el usuario da clic en "Aceptar términos y condiciones".
 * - Valida que el token exista.
 * - Verifica que no esté vencido.
 * - Marca la solicitud como ACEPTADA.
 * - Guarda fecha, IP y user-agent.
 */
router.post('/api/tyc/:token/aceptar', async (req, res) => {
  const { token } = req.params;

  const getClientIp = (req) => {
    const xf = req.headers['x-forwarded-for'];
    let ip = Array.isArray(xf) ? xf[0] : (xf ? String(xf).split(',')[0].trim() : null);
    ip = ip || req.ip || req.socket?.remoteAddress || null;
    if (ip && ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
    return ip;
  };

  try {
    // 1) Intentar memoria primero
    let solicitud = solicitudesTyC.get(token);

    // 2) Si no está en memoria, cargar desde BD
    if (!solicitud) {
      const r = await pool.query(
        `SELECT
          tyc_solicitud_id,
          precliente_id,
          token,
          canal,
          webhook_url,
          metadata,
          estado,
          created_at,
          expires_at,
          opened_at,
          accepted_at,
          accepted_ip
        FROM tyc_solicitudes
        WHERE token = $1
        LIMIT 1`,
        [token]
      );

      if (r.rowCount === 0) {
        return res.status(404).json({ ok: false, error: 'Solicitud no encontrada' });
      }

      const row = r.rows[0];

      solicitud = {
        tycSolicitudId: row.tyc_solicitud_id,
        preclienteId: row.precliente_id,
        canal: row.canal,
        token: row.token,
        estado: row.estado,
        createdAt: row.created_at?.toISOString?.() ?? String(row.created_at),
        expiresAt: row.expires_at?.toISOString?.() ?? String(row.expires_at),
        webhookUrl: row.webhook_url,
        metadata: row.metadata || {},
        openedAt: row.opened_at ? (row.opened_at.toISOString?.() ?? String(row.opened_at)) : null,
        acceptedAt: row.accepted_at ? (row.accepted_at.toISOString?.() ?? String(row.accepted_at)) : null,
        acceptedIp: row.accepted_ip || null,
        acceptedUserAgent: null, // en BD no lo guardamos (por ahora)
      };

      solicitudesTyC.set(token, solicitud);
    }

    const ahora = new Date();
    const expira = new Date(solicitud.expiresAt);

    // 3) Si ya expiró y no estaba aceptada, la marcamos EXPIRADA (BD + memoria)
    if (expira < ahora && solicitud.estado !== STATES.ACEPTADA) {
      const yaEstabaExpirada = solicitud.estado === STATES.EXPIRADA;

      if (!yaEstabaExpirada) {
        solicitud.estado = STATES.EXPIRADA;
        solicitudesTyC.set(token, solicitud);

        // Persistimos EXPIRADA en BD
        try {
          await pool.query(
            `UPDATE tyc_solicitudes
             SET estado = $2
             WHERE token = $1`,
            [token, STATES.EXPIRADA]
          );
        } catch (err) {
          console.error('[TyC] Error actualizando EXPIRADA en BD (POST /aceptar):', err);
        }

        // Avisamos a n8n que esta solicitud expiró (una vez)
        sendWebhook(solicitud, 'TYC_EXPIRADA').catch((err) => {
          console.error('Error en webhook TYC_EXPIRADA (POST /aceptar):', err.message);
        });
      }

      return res.status(410).json({
        ok: false,
        error: 'La URL ya expiró. Solicita una nueva.'
      });
    }

    // 4) Si ya estaba aceptada antes, respondemos ok
    if (solicitud.estado === STATES.ACEPTADA || solicitud.acceptedAt) {
      return res.json({
        ok: true,
        mensaje: 'Esta solicitud ya había sido aceptada previamente.',
        preclienteId: solicitud.preclienteId,
        tycSolicitudId: solicitud.tycSolicitudId,
        acceptedAt: solicitud.acceptedAt
      });
    }

    // 5) Persistir aceptación en BD (idempotente)
    const ip = getClientIp(req);
    const ua = req.headers['user-agent'] || null;

    const upd = await pool.query(
      `UPDATE tyc_solicitudes
       SET accepted_at = NOW(),
           accepted_ip = $2,
           estado = $3
       WHERE token = $1
         AND accepted_at IS NULL
       RETURNING accepted_at`,
      [token, ip, STATES.ACEPTADA]
    );

    const acceptedAtIso =
      upd.rowCount > 0
        ? (upd.rows[0].accepted_at?.toISOString?.() ?? String(upd.rows[0].accepted_at))
        : nowIso();

    // 6) Actualizar memoria
    solicitud.estado = STATES.ACEPTADA;
    solicitud.acceptedAt = acceptedAtIso;
    solicitud.acceptedIp = ip;
    solicitud.acceptedUserAgent = ua;
    solicitudesTyC.set(token, solicitud);

    // Log en consola
    console.log('✅ Solicitud TyC aceptada:', {
      preclienteId: solicitud.preclienteId,
      tycSolicitudId: solicitud.tycSolicitudId,
      acceptedAt: solicitud.acceptedAt,
      acceptedIp: solicitud.acceptedIp
    });

    // 7) Enviar webhook a n8n
    sendWebhook(solicitud, 'TYC_ACEPTADA').catch((err) => {
      console.error('Error en webhook TYC_ACEPTADA:', err.message);
    });

    return res.json({
      ok: true,
      mensaje: 'Aceptación registrada',
      preclienteId: solicitud.preclienteId,
      tycSolicitudId: solicitud.tycSolicitudId,
      acceptedAt: solicitud.acceptedAt,
      acceptedIp: solicitud.acceptedIp
    });
  } catch (err) {
    console.error('[TyC] Error en POST /api/tyc/:token/aceptar:', err);
    return res.status(500).json({ ok: false, error: 'Error interno' });
  }
});

/**
 * POST /api/tyc/cron/check-expired
 *
 * Lo puede llamar n8n cada X minutos.
 * - Revisa todas las solicitudes en memoria.
 * - Si están en CREADA o ABIERTA y ya expiraron, las marca como EXPIRADA.
 * - Envía webhook TYC_EXPIRADA para cada una.
 */
router.post('/api/tyc/cron/check-expired', requireInternalSecret, async (req, res) => {
  const ahora = new Date();
  let contador = 0;

  const tokens = Array.from(solicitudesTyC.keys());

  for (const token of tokens) {
    const solicitud = solicitudesTyC.get(token);
    if (!solicitud) continue;

    const expira = new Date(solicitud.expiresAt);

    if (
      (solicitud.estado === STATES.CREADA || solicitud.estado === STATES.ABIERTA) &&
      expira < ahora
    ) {
      solicitud.estado = STATES.EXPIRADA;
      solicitudesTyC.set(token, solicitud);

      try {
        await sendWebhook(solicitud, 'TYC_EXPIRADA');
      } catch (err) {
        console.error('Error en webhook TYC_EXPIRADA (cron):', err.message);
      }

      contador++;
    }
  }

  return res.json({
    ok: true,
    expiradas: contador
  });
});

module.exports = {
  router,
  solicitudesTyC
};
