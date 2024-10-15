// Función para obtener el token de autenticación (por ejemplo, desde el almacenamiento local)
function obtenerToken() {
    return localStorage.getItem('token'); // Cambia esto si almacenas el token de otra manera
}

async function getUsuarios() {
    try {
        const token = obtenerToken();
        if (!token) {
            alert('Por favor, inicie sesión primero.');
            return;
        }
        
        const response = await fetch('/api/usuarios', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`, // Incluir el token en las cabeceras
                'Content-Type': 'application/json' // Asegúrate de incluir el tipo de contenido adecuado
            }
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                alert('Token inválido o sesión expirada. Por favor, inicie sesión de nuevo.');
                localStorage.removeItem('token'); // Eliminar el token del almacenamiento local
                // Redirigir a la página de inicio de sesión si es necesario
            } else {
                throw new Error(`Error: ${response.status} ${response.statusText}`);
            }
        }
        
        const usuarios = await response.json();
        const usuariosList = document.getElementById('usuarios-list');
        usuariosList.innerHTML = '';
        usuarios.forEach(usuario => {
            const li = document.createElement('li');
            li.textContent = `ID: ${usuario.id}, Nombre: ${usuario.nombre}`;
            usuariosList.appendChild(li);
        });
    } catch (error) {
        console.error('Error al obtener usuarios:', error);
        alert('Ocurrió un error al obtener los usuarios. Por favor, inténtalo más tarde.');
    }
}

async function getMascotas() {
    try {
        const token = obtenerToken();
        if (!token) {
            alert('Por favor, inicie sesión primero.');
            return;
        }
        
        const response = await fetch('/api/mascotas', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`, // Incluir el token en las cabeceras
                'Content-Type': 'application/json' // Asegúrate de incluir el tipo de contenido adecuado
            }
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                alert('Token inválido o sesión expirada. Por favor, inicie sesión de nuevo.');
                localStorage.removeItem('token'); // Eliminar el token del almacenamiento local
                // Redirigir a la página de inicio de sesión si es necesario
            } else {
                throw new Error(`Error: ${response.status} ${response.statusText}`);
            }
        }
        
        const mascotas = await response.json();
        const mascotasList = document.getElementById('mascotas-list');
        mascotasList.innerHTML = '';
        mascotas.forEach(mascota => {
            const li = document.createElement('li');
            li.textContent = `ID: ${mascota.id}, Nombre: ${mascota.nombre}`;
            mascotasList.appendChild(li);
        });
    } catch (error) {
        console.error('Error al obtener mascotas:', error);
        alert('Ocurrió un error al obtener las mascotas. Por favor, inténtalo más tarde.');
    }
}

// Función para cerrar sesión
function logout() {
    localStorage.removeItem('token'); // Eliminar el token
    alert('Has cerrado sesión.');
    // Redirigir a la página de inicio de sesión o actualizar la vista
}

// Código para el formulario de inicio de sesión
document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const contacto = document.getElementById('username').value; // Cambiado a contacto
    const contraseña = document.getElementById('password').value; // Cambiado a contraseña

    fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ contacto, contraseña }) // Cambiado aquí también
    })
    .then(response => response.json())
    .then(data => {
        if (data.token) {
            localStorage.setItem('token', data.token);
            showFunctions(data.role);
        } else {
            alert('Inicio de sesión fallido');
        }
    });
});

// Mostrar funciones basadas en el rol
function showFunctions(role) {
    if (role === 'admin') {
        document.getElementById('adminFunctions').style.display = 'block';
    } else {
        document.getElementById('userFunctions').style.display = 'block';
    }
}





