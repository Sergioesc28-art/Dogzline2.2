const fs = require('fs');
const path = require('path');

// Ruta al archivo de datos
const dataPath = path.join(__dirname, '../data/data.json');

// Función para leer los datos
const readData = () => {
    const data = fs.readFileSync(dataPath, 'utf-8');
    return JSON.parse(data);
};

// Función para escribir los datos
const writeData = (data) => {
    fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));
};

module.exports = { readData, writeData };
