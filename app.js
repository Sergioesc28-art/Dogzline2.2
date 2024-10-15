const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const path = require('path');
const routes = require('./routes/ruta'); // Tus rutas
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken'); // Importar jsonwebtoken
const fs = require('fs');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const PORT = process.env.PORT || 3000;
require('dotenv').config();

const SECRET_KEY = process.env.JWT_SECRET || '_clave_secreta'; // Cambia esto a una clave secreta fuerte

// Configuración de Swagger
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Documentation',
      version: '1.0.0',
      description: 'API Information',
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
      },
    ],
  },
  apis: ['./routes/*.js'], // Ruta a tus archivos de rutas
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Middleware para servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Middleware para registro de solicitudes HTTP
app.use(morgan('dev'));

// Middleware para parsear JSON y datos de formularios
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuración de CORS
const corsOptions = {
  origin: '*', // Cambia esto a un origen específico si es necesario
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// Aplicar CORS a todas las rutas
app.use(cors(corsOptions));

// Ruta para la raíz del sitio web
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Endpoint para inicio de sesión
/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Iniciar sesión
 *     description: Endpoint para iniciar sesión
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               contacto:
 *                 type: string
 *               contraseña:
 *                 type: string
 *     responses:
 *       200:
 *         description: Inicio de sesión exitoso
 *       401:
 *         description: Credenciales incorrectas
 */
app.post('/api/login', (req, res) => {
  const { contacto, contraseña } = req.body;

  // Leer usuarios de usuarios.json
  fs.readFile('./data/usuarios.json', 'utf-8', (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Error al leer los usuarios' });
    }

    const usuarios = JSON.parse(data);
    const usuario = usuarios.find(u => u.contacto === contacto);

    if (usuario && usuario.contraseña === contraseña) {
      // Generar un token incluyendo el rol
      const token = jwt.sign({ id: usuario.id, role: usuario.role }, SECRET_KEY, { expiresIn: '1h' }); // Token válido por 1 hora
      res.json({ token, role: usuario.role }); // Incluye el rol en la respuesta
    } else {
      res.status(401).json({ message: 'Credenciales incorrectas' });
    }
  });
});

// Middleware para verificar el token
function verificarToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1]; // Obtener el token de la cabecera

  if (!token) {
    return res.status(403).json({ message: 'Token no proporcionado' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Token inválido' });
    }
    req.userId = decoded.id; // Almacenar el ID del usuario en la solicitud
    req.role = decoded.role; // Almacenar el rol del usuario en la solicitud
    next(); // Continuar con la siguiente función de middleware o ruta
  });
}

// Usar rutas de usuarios y mascotas, excluyendo el endpoint de login del middleware de verificación de token
app.use('/api', (req, res, next) => {
  if (req.path === '/login') {
    return next();
  }
  verificarToken(req, res, next);
}, routes);

// Middleware para manejar rutas no encontradas (404)
app.use((req, res, next) => {
  res.status(404).json({ message: 'Ruta no encontrada' });
});

// Manejo de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Algo salió mal!');
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
