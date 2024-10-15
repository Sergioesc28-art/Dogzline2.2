const express = require('express');
const router = express.Router();
const controllers = require('../controllers/controllers');
const jwt = require('jsonwebtoken');

// Middleware para verificar el token y si el usuario es administrador
function verificarAdmin(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];

    if (!token) return res.status(401).json({ mensaje: 'No autorizado' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ mensaje: 'Token inválido' });

        if (user.role !== 'admin') {
            return res.status(403).json({ mensaje: 'Acceso denegado. Solo administradores pueden realizar esta acción.' });
        }

        req.user = user;
        next();
    });
}

// Rutas de usuarios
router.get('/usuarios', controllers.getAllUsuarios);
router.get('/usuarios/:id', controllers.getUsuarioById);

// Rutas de mascotas
router.get('/mascotas', controllers.getAllMascotas);
router.get('/mascotas/:id', controllers.getMascotaById);
router.delete('/mascotas/:id', verificarAdmin, controllers.deleteMascotaById); // Añadir ruta DELETE

module.exports = router;