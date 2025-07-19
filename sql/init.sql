CREATE TABLE IF NOT EXISTS llaves_publicas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    nombre_clave VARCHAR(255) NOT NULL,
    llave TEXT NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id), -- Cada usuario solo puede tener una
    FOREIGN KEY (user_id) REFERENCES usuarios(id)
);


CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activo BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS archivos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(255),
    ruta TEXT,
    hash VARCHAR(64),
    usuario_id INT,
    fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firmas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    archivo_id INT,
    firma BLOB,
    usuario_id INT,
    fecha_firma TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
