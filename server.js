// server.js
require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const { router: tycRouter } = require('./tycRoutes');

const app = express();
const PORT = process.env.PORT || 3002;

// Middlewares
app.use(morgan('dev'));
app.use(cors());
app.use(express.json());
app.use(tycRouter);

// Endpoint simple de salud
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'ama-tyc-service',
    env: process.env.NODE_ENV || 'development'
  });
});

app.use(tycRouter);

app.listen(PORT, () => {
  console.log(`AMA TyC Service escuchando en puerto ${PORT}`);
});
