from flask import Flask, request, render_template, send_file, jsonify, session, redirect, url_for
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import create_engine, text

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_muy_segura'  # Cambiar por una clave segura
PRIVATE_FOLDER = "private_keys"
os.makedirs(PRIVATE_FOLDER, exist_ok=True)

# Clave secreta para JWT (en producción usar variable de entorno)
JWT_SECRET_KEY = 'jwt_secret_key_muy_segura'
JWT_ALGORITHM = 'HS256'

# Conexión a MySQL
engine = create_engine("mysql+pymysql://diplomado:diplomado@persistencia:3306/persistencia")

def generate_jwt_token(user_id, username):
    """Genera un token JWT para el usuario"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Expira en 1 hora
        'iat': datetime.datetime.utcnow(),  # Fecha de emisión
        'iss': 'diplomado-jwt-app'  # Emisor
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token):
    """Verifica un token JWT"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expirado
    except jwt.InvalidTokenError:
        return None  # Token inválido

def jwt_required(f):
    """Decorador para rutas que requieren autenticación JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Intentar obtener token del header Authorization
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
        
        # Si no hay token en header, intentar obtenerlo de la sesión
        if not token and 'jwt_token' in session:
            token = session['jwt_token']
        
        # Si no hay token, redirigir al login
        if not token:
            if request.is_json:
                return jsonify({'error': 'Token requerido'}), 401
            else:
                return redirect(url_for('login'))
        
        payload = verify_jwt_token(token)
        if not payload:
            # Token inválido, limpiar sesión y redirigir
            session.clear()
            if request.is_json:
                return jsonify({'error': 'Token inválido o expirado'}), 401
            else:
                return redirect(url_for('login'))
        
        # Agregar información del usuario al request
        request.current_user = payload
        return f(*args, **kwargs)
    
    return decorated

# Rutas de autenticación
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            if request.is_json:
                return jsonify({'error': 'Todos los campos son requeridos'}), 400
            else:
                return render_template('register.html', error='Todos los campos son requeridos')
        
        # Verificar si el usuario ya existe
        with engine.connect() as conn:
            existing_user = conn.execute(
                text("SELECT id FROM usuarios WHERE username = :username OR email = :email"),
                {"username": username, "email": email}
            ).fetchone()
            
            if existing_user:
                if request.is_json:
                    return jsonify({'error': 'Usuario o email ya existe'}), 400
                else:
                    return render_template('register.html', error='Usuario o email ya existe')
            
            # Crear nuevo usuario
            password_hash = generate_password_hash(password)
            conn.execute(
                text("INSERT INTO usuarios (username, email, password_hash) VALUES (:username, :email, :password_hash)"),
                {"username": username, "email": email, "password_hash": password_hash}
            )
            conn.commit()
        
        # Si es una petición JSON (API), devolver JSON
        if request.is_json:
            return jsonify({'message': 'Usuario registrado exitosamente'}), 201
        else:
            # Si es formulario HTML, mostrar mensaje y redirigir al login
            return render_template('register.html', 
                                 success='Usuario registrado exitosamente. Redirigiendo al login...', 
                                 redirect_to_login=True)
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            if request.is_json:
                return jsonify({'error': 'Username y password son requeridos'}), 400
            else:
                return render_template('login.html', error='Username y password son requeridos')
        
        # Verificar credenciales
        with engine.connect() as conn:
            user = conn.execute(
                text("SELECT id, username, password_hash FROM usuarios WHERE username = :username AND activo = TRUE"),
                {"username": username}
            ).fetchone()
            
            if user and check_password_hash(user[2], password):
                # Generar JWT token
                token = generate_jwt_token(user[0], user[1])
                
                # Si es una petición JSON (API), devolver JSON
                if request.is_json:
                    return jsonify({
                        'message': 'Login exitoso',
                        'token': token,
                        'user_id': user[0],
                        'username': user[1]
                    }), 200
                else:
                    # Si es formulario HTML, guardar token en sesión y redirigir
                    session['jwt_token'] = token
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    return redirect(url_for('index'))
            else:
                if request.is_json:
                    return jsonify({'error': 'Credenciales inválidas'}), 401
                else:
                    return render_template('login.html', error='Credenciales inválidas')
    
    return render_template('login.html')

# Ruta protegida requiere JWT
@app.route("/", methods=["GET", "POST"])
@jwt_required
def index():
    if request.method == "POST":
        nombre = request.form["nombre_clave"]

        # Generar llaves
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Serializar
        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        pub_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Guardar pública en base de datos
        with engine.connect() as conn:
            conn.execute(text("INSERT INTO llaves_publicas (nombre_clave, llave) VALUES (:nombre, :llave)"),
                         {"nombre": nombre, "llave": pub_pem.decode("utf-8")})
            conn.commit()

        # Guardar privada y ofrecer descarga
        priv_path = os.path.join(PRIVATE_FOLDER, f"{nombre}_private.pem")
        with open(priv_path, "wb") as f:
            f.write(priv_pem)

        return send_file(priv_path, as_attachment=True)

    # Obtener información del usuario para mostrar en la página
    username = request.current_user.get('username', 'Usuario')
    return render_template("index.html", username=username)

# Ruta para logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Ruta para verificar token
@app.route('/verify-token', methods=['POST'])
def verify_token():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'valid': False, 'error': 'Token no proporcionado'}), 400
    
    if token.startswith('Bearer '):
        token = token[7:]
    
    payload = verify_jwt_token(token)
    if payload:
        return jsonify({'valid': True, 'payload': payload}), 200
    else:
        return jsonify({'valid': False, 'error': 'Token inválido o expirado'}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=("cert.pem", "key.pem"))