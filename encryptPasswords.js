const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const dataPathUsuarios = path.join(__dirname, 'data/usuarios.json');

const usuarios = [
    { contacto: 'yoselinalamilla3@gmail.com', contraseña: 'Yoselin123' },
    { contacto: 'Marbellaterraza729@gmail.com', contraseña: 'Marbella456' }
];

usuarios.forEach(usuario => {
    const hashedPassword = bcrypt.hashSync(usuario.contraseña, 10);
    console.log(`Contacto: ${usuario.contacto}, Contraseña encriptada: ${hashedPassword}`);
});

// Leer el archivo usuarios.json
const data = fs.readFileSync(dataPathUsuarios, 'utf-8');
const usuariosJson = JSON.parse(data);

// Actualizar las contraseñas encriptadas en usuarios.json
usuariosJson.forEach(usuario => {
    const user = usuarios.find(u => u.contacto === usuario.contacto);
    if (user) {
        usuario.contraseña = bcrypt.hashSync(user.contraseña, 10);
    }
});

// Guardar el archivo usuarios.json actualizado
fs.writeFileSync(dataPathUsuarios, JSON.stringify(usuariosJson, null, 2));
console.log('Contraseñas encriptadas y guardadas en usuarios.json');