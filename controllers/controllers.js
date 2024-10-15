const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Ruta de los datos
const dataPathUsuarios = path.join(__dirname, '../data/usuarios.json');
const dataPathMascotas = path.join(__dirname, '../data/mascotas.json');

// Funciones para cargar y guardar usuarios
const loadUsers = () => {
    const data = fs.readFileSync(dataPathUsuarios, 'utf-8');
    return JSON.parse(data);
};

const saveUsers = (users) => {
    fs.writeFileSync(dataPathUsuarios, JSON.stringify(users, null, 2));
};

// Funciones para cargar y guardar mascotas
const loadMascotas = () => {
    const data = fs.readFileSync(dataPathMascotas, 'utf-8');
    try {
        const parsedData = JSON.parse(data);
        if (!Array.isArray(parsedData.mascotas)) {
            throw new Error('El contenido de mascotas.json no es un array');
        }
        return parsedData.mascotas;
    } catch (error) {
        console.error('Error al cargar las mascotas:', error);
        return [];
    }
};

const saveMascotas = (mascotas) => {
    const data = { mascotas };
    fs.writeFileSync(dataPathMascotas, JSON.stringify(data, null, 2));
};

// Función de inicio de sesión
exports.login = (req, res) => {
    const { contacto, contraseña } = req.body;
    const users = loadUsers(); // Cargar usuarios desde el archivo JSON

    const user = users.find(u => u.contacto === contacto);
    if (!user) {
        return res.status(401).json({ mensaje: 'Usuario o contraseña incorrectos' });
    }

    const isPasswordValid = bcrypt.compareSync(contraseña, user.contraseña);
    if (!isPasswordValid) {
        return res.status(401).json({ mensaje: 'Usuario o contraseña incorrectos' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
        expiresIn: '1h'
    });

    res.json({ token });
};

// Rutas para usuarios
exports.getAllUsuarios = (req, res) => {
    const users = loadUsers();
    res.json(users);
};

exports.getUsuarioById = (req, res) => {
    const id = parseInt(req.params.id);
    const users = loadUsers();
    const user = users.find(u => u.id === id);
    if (!user) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json(user);
};

// Rutas para mascotas
exports.getAllMascotas = (req, res) => {
    const mascotas = loadMascotas();
    res.json(mascotas);
};

exports.getMascotaById = (req, res) => {
    const id = parseInt(req.params.id);
    const mascotas = loadMascotas();
    if (!Array.isArray(mascotas)) {
        return res.status(500).json({ message: 'Error al cargar las mascotas' });
    }
    const mascota = mascotas.find(m => m.id === id);
    if (mascota) {
        res.json(mascota);
    } else {
        res.status(404).send('Mascota no encontrada');
    }
};

exports.createMascota = (req, res) => {
    const mascotas = loadMascotas();
    const newMascota = req.body;
    newMascota.id = mascotas.length ? mascotas[mascotas.length - 1].id + 1 : 1;
    mascotas.push(newMascota);
    saveMascotas(mascotas);
    res.status(201).json(newMascota);
};

exports.updateMascota = (req, res) => {
    const mascotas = loadMascotas();
    const index = mascotas.findIndex(m => m.id === parseInt(req.params.id));
    if (index !== -1) {
        mascotas[index] = { ...mascotas[index], ...req.body };
        saveMascotas(mascotas);
        res.json(mascotas[index]);
    } else {
        res.status(404).send('Mascota no encontrada');
    }
};

exports.deleteMascota = (req, res) => {
    const mascotas = loadMascotas();
    const index = mascotas.findIndex(m => m.id === parseInt(req.params.id));
    if (index !== -1) {
        const deletedMascota = mascotas.splice(index, 1);
        saveMascotas(mascotas);
        res.json(deletedMascota);
    } else {
        res.status(404).send('Mascota no encontrada');
    }
};

// Controlador para eliminar una mascota por ID
exports.deleteMascotaById = (req, res) => {
    const id = parseInt(req.params.id, 10);

    fs.readFile(path.join(__dirname, '../data/mascotas.json'), 'utf-8', (err, data) => {
        if (err) {
            return res.status(500).json({ message: 'Error al leer las mascotas' });
        }

        let mascotas = JSON.parse(data);
        const mascotaIndex = mascotas.findIndex(m => m.id === id);

        if (mascotaIndex === -1) {
            return res.status(404).json({ message: 'Mascota no encontrada' });
        }

        mascotas.splice(mascotaIndex, 1);

        fs.writeFile(path.join(__dirname, '../data/mascotas.json'), JSON.stringify(mascotas, null, 2), (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error al guardar las mascotas' });
            }

            res.json({ message: 'Mascota eliminada' });
        });
    });
};