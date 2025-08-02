import base64
import datetime  # Manejo de fechas y tiempos
import hashlib  # Funciones hash, utilizado para calcular el hash de los archivos
import os  # Funciones del sistema operativo (crear directorios, unir rutas, etc.)
import secrets  # Para generar tokens y números seguros

from authlib.oauth2.rfc7636 import create_s256_code_challenge
from flask import send_file, after_this_request
from functools import wraps  # Para crear decoradores que modifican funciones
from urllib.parse import urlparse, urljoin
import jwt  # Manejo de JSON Web Tokens
from authlib.integrations.flask_client import OAuth  # Soporte para autenticación OAuth
from cryptography.hazmat.primitives import hashes  # Algoritmos de hash para criptografía
from cryptography.hazmat.primitives import serialization  # Serialización y deserialización de llaves
from cryptography.hazmat.primitives.asymmetric import padding  # Padding para procesos criptográficos (firmas)
from cryptography.hazmat.primitives.asymmetric import rsa  # Generación de claves RSA
from dotenv import load_dotenv  # Cargar variables de entorno desde un archivo .env
from flask import Flask, request, render_template, send_file, jsonify, session, redirect, url_for, \
    send_from_directory  # Funciones de Flask para manejo de rutas, sesiones y respuesta HTTP
from flask_login import LoginManager, UserMixin  # Facilita el manejo de la sesión de usuario
from sqlalchemy import create_engine, text  # Conexión a la base de datos y ejecución de consultas SQL
from werkzeug.security import generate_password_hash, \
    check_password_hash  # Funciones para hashear y validar contraseñas
from werkzeug.utils import secure_filename  # Asegura que el nombre del archivo sea válido

# Cargar variables de entorno del .env
load_dotenv()

app = Flask(__name__)
# Definir la clave secreta de la aplicación (usada para sesiones, etc.)
app.secret_key = 'tu_clave_secreta_muy_segura'
# Configuración para el uso de OAuth en la aplicación
oauth = OAuth(app)

# Directorios para almacenar llaves privadas, archivos subidos y firmas digitales
PRIVATE_FOLDER = "private_keys"
os.makedirs(PRIVATE_FOLDER, exist_ok=True)
UPLOAD_FOLDER = "archivos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
FIRMAS_FOLDER = "firmas"
os.makedirs(FIRMAS_FOLDER, exist_ok=True)

# Configuración para JWT: se genera una clave secreta y se define el algoritmo
JWT_SECRET_KEY = secrets.token_urlsafe(32)  # 256 bits de entropía
JWT_ALGORITHM = 'HS256'

# =========================
# Cookies & CSRF
# =========================
ACCESS_COOKIE_NAME = os.getenv("ACCESS_COOKIE_NAME", "access_token")
XSRF_COOKIE_NAME = os.getenv("XSRF_COOKIE_NAME", "XSRF-TOKEN")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() in ("1", "true", "yes", "on")
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "Lax")  # Lax | Strict | None
ACCESS_COOKIE_MAX_AGE = JWT_EXP_MINUTES * 60

def _set_auth_cookies(resp, token: str):
    """Setea cookie HttpOnly con el access token y cookie XSRF (no HttpOnly) para doble submit."""
    resp.set_cookie(
        ACCESS_COOKIE_NAME,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=ACCESS_COOKIE_MAX_AGE,
        path="/"
    )
    xsrf = secrets.token_urlsafe(32)
    resp.set_cookie(
        XSRF_COOKIE_NAME,
        xsrf,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=ACCESS_COOKIE_MAX_AGE,
        path="/"
    )
    return xsrf

def _clear_auth_cookies(resp):
    resp.delete_cookie(ACCESS_COOKIE_NAME, path="/")
    resp.delete_cookie(XSRF_COOKIE_NAME, path="/")

def csrf_protect(fn):
    """Protección CSRF (doble submit) para POST/PUT/PATCH/DELETE cuando usamos cookies."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            csrf_cookie = request.cookies.get(XSRF_COOKIE_NAME, "")
            csrf_in = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
            if not csrf_cookie or not csrf_in or csrf_cookie != csrf_in:
                return jsonify({"error": "CSRF token inválido"}), 403
        return fn(*args, **kwargs)
    return wrapper

# =========================
# Seguridad de respuestas (headers)
# =========================
@app.after_request
def set_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'")
    # HSTS si sirve por HTTPS (recomendado en prod)
    if COOKIE_SECURE:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp

# =========================
# DB
# =========================
# Conectar a MySQL mediante SQLAlchemy
engine = create_engine("mysql+pymysql://diplomado:diplomado@persistencia:3306/persistencia")

# Configuración de la autenticación con Google mediante OAuth
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={
        'access_type': 'offline',
        'code_challenge_method': 'S256'
    },
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},

)

# Inicialización del Login Manager para el manejo de sesión de usuarios
login_manager = LoginManager()
login_manager.init_app(app)


# Clase que representa el usuario, extiende de UserMixin para compatibilidad con Flask-Login
class User(UserMixin):
    def __init__(self, id_, name, email):
        self.id = id_
        self.name = name
        self.email = email


# Diccionario en memoria para almacenar usuarios
users = {}


@login_manager.user_loader
def load_user(user_id):
    # Función que carga el usuario en sesión según su id
    return users.get(user_id)


# ------------------------------------- JWT ---------------------------------------
def generate_jwt_token(user_id, username):
    """Genera un token JWT para el usuario, con datos básicos y tiempo de expiración."""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Token expira en 1 hora
        'iat': datetime.datetime.utcnow(),  # Fecha de emisión
        'iss': 'diplomado-jwt-app'  # Emisor del token
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token):
    """Verifica que el token JWT sea válido comprobando firma, expiración y emisor."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={
            "verify_exp": True,
            "verify_signature": True,
            "require": ["exp", "iat", "iss"],
        })
        if payload["iss"] != "diplomado-jwt-app":
            raise ValueError("Issuer inválido")
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def jwt_required(f):
    """Decorador para proteger rutas que requieren autenticación mediante JWT."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Se intenta extraer el token desde el encabezado Authorization
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
        # Si no se encontró, se revisa en la sesión
        if not token and 'jwt_token' in session:
            token = session['jwt_token']
        # 2) Fallback: cookie HttpOnly
        if not token:
            token = request.cookies.get(ACCESS_COOKIE_NAME)
        # En caso de no tener token se retorna error o se redirige al login
        if not token:
            if request.is_json:
                return jsonify({'error': 'Token requerido'}), 401
            else:
                return redirect(url_for('login'))
        payload = verify_jwt_token(token)
        if not payload:
            session.clear()
            if request.is_json:
                return jsonify({'error': 'Token inválido o expirado'}), 401
            else:
                return redirect(url_for('login'))
        # Se agrega la información del usuario a la solicitud
        request.current_user = payload
        return f(*args, **kwargs)

    return decorated


def make_pkce_pair():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge


# =========================
# Login manual: límite 3 intentos
# =========================
MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "3"))
LOCKOUT_SECONDS = int(os.getenv("LOGIN_LOCKOUT_SECONDS", "900"))
_login_attempts = {}  # clave "ip:usuario" -> {"count": int, "lock_until": epoch}

def _attempt_key(username: str) -> str:
    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
    usernorm = (username or "").strip().lower()
    return f"{ip}:{usernorm}"

def _is_locked(key: str):
    rec = _login_attempts.get(key)
    if not rec:
        return False, 0
    now = time.time()
    lock_until = rec.get("lock_until", 0)
    if lock_until and lock_until > now:
        return True, int(lock_until - now)
    return False, 0

def _register_fail(key: str):
    now = time.time()
    rec = _login_attempts.get(key, {"count": 0, "lock_until": 0})
    if rec.get("lock_until", 0) and rec["lock_until"] <= now:
        rec = {"count": 0, "lock_until": 0}
    rec["count"] = int(rec.get("count", 0)) + 1
    if rec["count"] >= MAX_ATTEMPTS:
        rec["lock_until"] = now + LOCKOUT_SECONDS
        rec["count"] = 0
        _login_attempts[key] = rec
        return True, LOCKOUT_SECONDS, 0
    else:
        _login_attempts[key] = rec
        remaining = MAX_ATTEMPTS - rec["count"]
        return False, 0, remaining

def _reset_attempts(key: str):
    _login_attempts.pop(key, None)

# =========================
# Util PKCE local (para referencia)
# =========================
def make_pkce_pair():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge


# ------------------------------------- Autenticación y Registro ---------------------------------------
# Ruta para iniciar sesión con Google
@app.route("/login/google")
def login_google():
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(64)

    code_challenge = create_s256_code_challenge(code_verifier)
    session['state'] = state
    session['nonce'] = nonce
    session['code_verifier'] = code_verifier

    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(
        redirect_uri,
        nonce=nonce,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method='S256'
    )

@app.route("/debug-token")
@jwt_required
def debug_token():
    return jsonify({"jwt_token": session.get("jwt_token")})



# Ruta de autorización para validar la respuesta de Google
@app.route("/authorize/google")
def authorize_google():
    # Verificación del parámetro `state` para prevenir CSRF
    state_received = request.args.get("state")
    state_expected = session.get("state")
    if not state_received or state_received != state_expected:
        return "Posible ataque CSRF detectado", 403
    code_verifier = session.pop('code_verifier', None)
    token = oauth.google.authorize_access_token(code_verifier=code_verifier)
    nonce = session.get('nonce')
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    email = user_info.get("email")
    nombre = user_info.get("name") or email.split("@")[0]

    with engine.connect() as conn:
        # Se consulta la base de datos buscando al usuario por email
        result = conn.execute(text("SELECT id, username FROM usuarios WHERE email = :email"),
                              {"email": email}).fetchone()

        if not result:
            # Si el usuario no existe, se registra automáticamente
            username = nombre.replace(" ", "_").lower()
            conn.execute(
                text("INSERT INTO usuarios (username, email, password_hash, activo) VALUES (:u, :e, '', TRUE)"), {
                    "u": username,
                    "e": email
                })
            conn.commit()
            result = conn.execute(text("SELECT id, username FROM usuarios WHERE email = :email"),
                                  {"email": email}).fetchone()

        user_id, username = result
        # Se genera el token JWT para el usuario
        token_jwt = generate_jwt_token(user_id, username)

        # Guardar datos del usuario en la sesión
        session['jwt_token'] = token_jwt
        session['user_id'] = user_id
        session['username'] = username

    return redirect(url_for('index'))


# Ruta para el registro de nuevos usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        # Validar que todos los campos se hayan completado
        if not username or not email or not password:
            if request.is_json:
                return jsonify({'error': 'Todos los campos son requeridos'}), 400
            else:
                return render_template('register.html', error='Todos los campos son requeridos')

        with engine.connect() as conn:
            # Verificar si ya existe un usuario con el mismo username o email
            existing_user = conn.execute(
                text("SELECT id FROM usuarios WHERE username = :username OR email = :email"),
                {"username": username, "email": email}
            ).fetchone()

            if existing_user:
                if request.is_json:
                    return jsonify({'error': 'Usuario o email ya existe'}), 400
                else:
                    return render_template('register.html', error='Usuario o email ya existe')

            # Crear el usuario, almacenando la contraseña hasheada para mayor seguridad
            password_hash = generate_password_hash(password)
            conn.execute(
                text(
                    "INSERT INTO usuarios (username, email, password_hash) VALUES (:username, :email, :password_hash)"),
                {"username": username, "email": email, "password_hash": password_hash}
            )
            conn.commit()

        if request.is_json:
            return jsonify({'message': 'Usuario registrado exitosamente'}), 201
        else:
            return render_template('register.html',
                                   success='Usuario registrado exitosamente. Redirigiendo al login...',
                                   redirect_to_login=True)

    return render_template('register.html')


# =========================
# Login manual (usuario/contraseña) con cookies + lockout
# =========================
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

        # Anti-fuerza bruta (solo para login manual)
        key = _attempt_key(username)
        locked, seconds_left = _is_locked(key)
        if locked:
            msg = f"Demasiados intentos fallidos. Intenta de nuevo en {seconds_left} segundos."
            if request.is_json:
                return jsonify({'error': msg}), 429
            else:
                return render_template('login.html', error=msg), 429

        with engine.connect() as conn:
            user = conn.execute(
                text("SELECT id, username, password_hash FROM usuarios WHERE username = :username AND activo = TRUE"),
                {"username": username}
            ).fetchone()

        if user and check_password_hash(user[2], password):
            _reset_attempts(key)
            token = generate_jwt_token(user[0], user[1])

            # [CAMBIO] Establecer cookies de autenticación
            if request.is_json:
                resp = make_response(jsonify({'message': 'Login exitoso', 'user_id': user[0], 'username': user[1]}))
            else:
                resp = make_response(redirect(url_for('index')))

            _set_auth_cookies(resp, token)
            # (opcional) info mínima en sesión
            session['user_id'] = user[0]
            session['username'] = user[1]
            return resp
        else:
            just_locked, lock_secs, remaining = _register_fail(key)
            if just_locked:
                msg = f"Cuenta bloqueada temporalmente por intentos fallidos. Intenta de nuevo en {lock_secs} segundos."
                if request.is_json:
                    return jsonify({'error': msg}), 429
                else:
                    return render_template('login.html', error=msg), 429
            else:
                msg = f"Credenciales inválidas. Intentos restantes: {remaining}"
                if request.is_json:
                    return jsonify({'error': msg}), 401
                else:
                    return render_template('login.html', error=msg), 401

    return render_template('login.html')

# =========================
# Logout (limpia cookies) – protegido con CSRF
# =========================
@app.route('/logout', methods=["POST"])
@csrf_protect
def logout():
    session.clear()
    resp = make_response(jsonify({"ok": True, "message": "Logout"}))
    _clear_auth_cookies(resp)
    return resp


# Ruta principal protegida (requiere JWT)
@app.route("/", methods=["GET", "POST"])
@jwt_required
def index():
    user_id = request.current_user.get('user_id')
    username = request.current_user.get('username', 'Usuario')

    if request.method == "POST":
        nombre = request.form["nombre_clave"]

        with engine.connect() as conn:
            # Se verifica si el usuario ya generó una llave (para evitar duplicados)
            existing = conn.execute(
                text("SELECT id FROM llaves_publicas WHERE user_id = :uid"),
                {"uid": user_id}
            ).fetchone()

            if existing:
                return render_template("index.html", username=username, error="Ya has generado una llave.")

            # Generar un par de llaves RSA (privada y pública)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            # Serializar la llave privada a formato PEM
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            # Serializar la llave pública a formato PEM
            pub_pem = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Guardar la llave pública en la base de datos para futuras verificaciones
            conn.execute(text("""
                              INSERT INTO llaves_publicas (user_id, nombre_clave, llave)
                              VALUES (:uid, :nombre, :llave)
                              """), {"uid": user_id, "nombre": nombre, "llave": pub_pem.decode("utf-8")})
            conn.commit()

        # Guardar la llave privada temporalmente para enviarla al usuario
        priv_path = os.path.join(PRIVATE_FOLDER, f"{nombre}_private.pem")
        with open(priv_path, "wb") as f:
            f.write(priv_pem)

        # Configurar para eliminar el archivo después de enviarlo
        @after_this_request
        def remove_file(response):
            try:
                os.remove(priv_path)
                print(f"Llave privada temporal eliminada: {priv_path}")
            except Exception as error:
                print(f"Error eliminando llave privada temporal: {error}")
            return response

        # Enviar el archivo al usuario
        return send_file(
            priv_path,
            as_attachment=True,
            download_name=f"{nombre}_private.pem",
            mimetype='application/x-pem-file'
        )

    # Código para GET requests - mostrar la página principal
    with engine.connect() as conn:
        archivos_propios = conn.execute(text("""
                                             SELECT DISTINCT a.id,
                                                             a.nombre,
                                                             a.hash,
                                                             a.fecha_subida,
                                                             'Propio'   as tipo,
                                                             u.username as propietario
                                             FROM archivos a
                                                      JOIN usuarios u ON a.usuario_id = u.id
                                             WHERE a.usuario_id = :usuario_id
                                             """), {"usuario_id": user_id}).fetchall()

        archivos_compartidos = conn.execute(text("""
                                                 SELECT DISTINCT a.id,
                                                                 a.nombre,
                                                                 a.hash,
                                                                 a.fecha_subida,
                                                                 'Compartido' as tipo,
                                                                 u.username   as propietario
                                                 FROM archivos a
                                                          JOIN archivos_compartidos ac ON a.id = ac.archivo_id
                                                          JOIN usuarios u ON a.usuario_id = u.id
                                                 WHERE ac.compartido_con_id = :usuario_id
                                                 """), {"usuario_id": user_id}).fetchall()

        # Combinar archivos propios y compartidos
        todos_archivos = list(archivos_propios) + list(archivos_compartidos)

        archivos_con_firmas = []
        for archivo in todos_archivos:
            archivo_dict = {
                'id': archivo.id,
                'nombre': archivo.nombre,
                'hash': archivo.hash,
                'fecha_subida': archivo.fecha_subida,
                'tipo': archivo.tipo,
                'propietario': archivo.propietario
            }

            # Obtener información de las firmas asociadas a cada archivo
            firmas = conn.execute(text("""
                                       SELECT u.username, f.fecha_firma, f.valida
                                       FROM firmas f
                                                JOIN usuarios u ON f.usuario_id = u.id
                                       WHERE f.archivo_id = :archivo_id
                                       ORDER BY f.fecha_firma DESC
                                       """), {"archivo_id": archivo.id}).fetchall()

            archivo_dict['firmas'] = [
                {
                    'usuario': firma.username,
                    'fecha': firma.fecha_firma,
                    'valida': firma.valida
                }
                for firma in firmas
            ]

            archivos_con_firmas.append(archivo_dict)

    # Renderizar la página principal con la lista de archivos
    return render_template("index.html", username=username, archivos=archivos_con_firmas)


def is_safe_redirect(target):
    host_url = request.host_url
    redirect_url = urljoin(host_url, target)
    return urlparse(redirect_url).scheme in ('http', 'https') and urlparse(host_url).netloc == urlparse(redirect_url).netloc


# Ruta para cerrar sesión y limpiar la sesión del usuario
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# Ruta que permite validar un token JWT enviado en la solicitud
@app.route('/verify-token', methods=['POST'])
def verify_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'valid': False, 'error': 'Token no proporcionado'}), 400

    token = auth_header.split(" ")[1]
    payload = verify_jwt_token(token)
    if payload:
        return jsonify({'valid': True, 'payload': payload}), 200
    else:
        return jsonify({'valid': False, 'error': 'Token inválido o expirado'}), 401


# --------------------------------- Rutas de archivos y firmas ---------------------------------
# Ruta para subir archivos al servidor
@app.route("/upload", methods=["POST"])
@jwt_required
def upload_file():
    if 'archivo' not in request.files:
        return jsonify({"error": "No se envió archivo"}), 400

    file = request.files['archivo']
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Calcular el hash SHA256 del archivo para verificar su integridad
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        sha256.update(f.read())
    hash_hex = sha256.hexdigest()

    with engine.connect() as conn:
        # Guardar la información del archivo en la base de datos
        conn.execute(text("""
                          INSERT INTO archivos (nombre, ruta, hash, usuario_id)
                          VALUES (:nombre, :ruta, :hash, :usuario_id)
                          """), {
                         "nombre": filename,
                         "ruta": filepath,
                         "hash": hash_hex,
                         "usuario_id": request.current_user['user_id']
                     })
        conn.commit()

    return jsonify({"message": "Archivo subido", "hash": hash_hex})


# Ruta para firmar un archivo mediante una llave privada proporcionada
@app.route("/firmar", methods=["POST"])
@jwt_required
def firmar_archivo():
    archivo_id = request.form.get("archivo_id")
    llave = request.files.get("llave")

    if not archivo_id or not llave:
        return jsonify({"error": "Datos incompletos"}), 400

    user_id = request.current_user['user_id']

    with engine.connect() as conn:
        # Verificar que el archivo exista y que el usuario tenga acceso (propio o compartido)
        result = conn.execute(text("""
                                   SELECT a.ruta, a.nombre
                                   FROM archivos a
                                   WHERE a.id = :id
                                     AND (
                                       a.usuario_id = :user_id
                                           OR EXISTS (SELECT 1
                                                      FROM archivos_compartidos ac
                                                      WHERE ac.archivo_id = a.id
                                                        AND ac.compartido_con_id = :user_id)
                                       )
                                   """), {"id": archivo_id, "user_id": user_id}).fetchone()

        if not result:
            return jsonify({"error": "Archivo no encontrado o sin permisos"}), 404

        ruta_archivo, nombre_archivo = result

        # Evitar que un usuario firme el mismo archivo más de una vez
        firma_existente = conn.execute(text("""
                                            SELECT id
                                            FROM firmas
                                            WHERE archivo_id = :archivo_id
                                              AND usuario_id = :user_id
                                            """), {"archivo_id": archivo_id, "user_id": user_id}).fetchone()

        if firma_existente:
            return jsonify({"error": "Ya has firmado este archivo"}), 400

    with open(ruta_archivo, "rb") as f:
        contenido = f.read()

    try:
        # Cargar la llave privada proporcionada en formato PEM
        private_key = serialization.load_pem_private_key(
            llave.read(),
            password=None
        )
    except Exception as e:
        return jsonify({"error": "Llave privada inválida"}), 400

    # Realizar la firma digital sobre el contenido del archivo
    firma = private_key.sign(
        contenido,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    ruta_firma = os.path.join(FIRMAS_FOLDER, f"{user_id}_{archivo_id}_{nombre_archivo}.firma")
    with open(ruta_firma, "wb") as f:
        f.write(firma)

    # Validar la firma utilizando la llave pública almacenada en la base de datos
    es_valida = True
    try:
        with engine.connect() as conn:
            llave_publica_row = conn.execute(text("""
                                                  SELECT llave
                                                  FROM llaves_publicas
                                                  WHERE user_id = :uid
                                                  """), {"uid": user_id}).fetchone()

            if llave_publica_row:
                public_key = serialization.load_pem_public_key(
                    llave_publica_row[0].encode("utf-8")
                )
                public_key.verify(
                    signature=firma,
                    data=contenido,
                    padding=padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    algorithm=hashes.SHA256()
                )
    except:
        es_valida = False

    with engine.connect() as conn:
        # Guardar la firma en la base de datos, indicando si esta es válida o no
        conn.execute(text("""
                          INSERT INTO firmas (archivo_id, firma, usuario_id, valida)
                          VALUES (:archivo_id, :firma, :usuario_id, :valida)
                          """), {
                         "archivo_id": archivo_id,
                         "firma": firma,
                         "usuario_id": user_id,
                         "valida": es_valida
                     })
        conn.commit()

    return jsonify({
        "message": "Archivo firmado",
        "ruta_firma": f"firmas/{os.path.basename(ruta_firma)}",
        "valida": es_valida
    })


# Ruta para descargar una firma almacenada en el servidor
@app.route('/firmas/<filename>')
def descargar_firma(filename):
    return send_from_directory('firmas', filename)


# Ruta para verificar la firma digital de un archivo
@app.route("/verificar", methods=["POST"])
@jwt_required
def verificar_firma():
    archivo_id = request.form.get("archivo_id")
    archivo_firma = request.files.get("firma")  # Firma digital provista por el usuario

    if not archivo_id or not archivo_firma:
        return jsonify({"error": "Faltan datos"}), 400

    firma_bytes = archivo_firma.read()

    with engine.connect() as conn:
        archivo_info = conn.execute(text("""
                                         SELECT nombre, ruta
                                         FROM archivos
                                         WHERE id = :aid
                                         """), {"aid": archivo_id}).fetchone()

        if not archivo_info:
            return jsonify({"error": "Archivo no encontrado"}), 404

        archivo_nombre, ruta_archivo = archivo_info

        try:
            with open(ruta_archivo, "rb") as f:
                contenido = f.read()
        except FileNotFoundError:
            return jsonify({"error": "Archivo original no encontrado en disco"}), 404

        # Obtener las llaves públicas de todos los usuarios que han firmado el archivo
        firmantes = conn.execute(text("""
                                      SELECT DISTINCT u.username, lp.llave
                                      FROM firmas f
                                               JOIN usuarios u ON f.usuario_id = u.id
                                               JOIN llaves_publicas lp ON lp.user_id = u.id
                                      WHERE f.archivo_id = :aid
                                      """), {"aid": archivo_id}).fetchall()

        if not firmantes:
            return jsonify({"error": "No hay firmas registradas para este archivo"}), 404

    # Se intenta verificar la firma con cada llave pública encontrada
    for firmante in firmantes:
        username, llave_publica_pem = firmante
        try:
            public_key = serialization.load_pem_public_key(llave_publica_pem.encode("utf-8"))
            public_key.verify(
                signature=firma_bytes,
                data=contenido,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            # Si la verificación es exitosa, se informa que la firma es válida
            return jsonify({
                "valido": True,
                "mensaje": "válida",
                "firmante": username,
                "detalles": f"Firma verificada correctamente. Firmado por: {username}"
            })
        except Exception:
            continue

    return jsonify({
        "valido": False,
        "mensaje": "inválida",
        "detalles": "La firma no corresponde a ningún usuario que haya firmado este archivo"
    })


# --------------------------------- Rutas para compartir archivos ---------------------------------
# Ruta para listar todos los usuarios activos (excepto el actual)
@app.route("/usuarios", methods=["GET"])
@jwt_required
def listar_usuarios():
    user_id = request.current_user['user_id']
    with engine.connect() as conn:
        usuarios = conn.execute(text("""
                                     SELECT id, username, email
                                     FROM usuarios
                                     WHERE id != :user_id
                                       AND activo = TRUE
                                     ORDER BY username
                                     """), {"user_id": user_id}).fetchall()

    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email
    } for u in usuarios])


# Ruta para compartir un archivo con otro usuario
@app.route("/compartir", methods=["POST"])
@jwt_required
def compartir_archivo():
    data = request.get_json() if request.is_json else request.form
    archivo_id = data.get('archivo_id')
    compartir_con_id = data.get('compartir_con_id')

    if not archivo_id or not compartir_con_id:
        return jsonify({"error": "Datos incompletos"}), 400

    user_id = request.current_user['user_id']

    with engine.connect() as conn:
        # Se verifica que el archivo pertenezca al usuario que intenta compartirlo
        archivo = conn.execute(text("""
                                    SELECT id
                                    FROM archivos
                                    WHERE id = :archivo_id
                                      AND usuario_id = :user_id
                                    """), {"archivo_id": archivo_id, "user_id": user_id}).fetchone()

        if not archivo:
            return jsonify({"error": "Archivo no encontrado o no tienes permisos"}), 404

        # Se revisa que el archivo no esté ya compartido con el usuario destino
        compartido = conn.execute(text("""
                                       SELECT id
                                       FROM archivos_compartidos
                                       WHERE archivo_id = :archivo_id
                                         AND compartido_con_id = :compartir_con_id
                                       """), {
                                      "archivo_id": archivo_id,
                                      "compartir_con_id": compartir_con_id
                                  }).fetchone()

        if compartido:
            return jsonify({"error": "El archivo ya está compartido con este usuario"}), 400

        # Registrar el compartir en la base de datos
        conn.execute(text("""
                          INSERT INTO archivos_compartidos
                              (archivo_id, propietario_id, compartido_con_id)
                          VALUES (:archivo_id, :propietario_id, :compartido_con_id)
                          """), {
                         "archivo_id": archivo_id,
                         "propietario_id": user_id,
                         "compartido_con_id": compartir_con_id
                     })
        conn.commit()

        # Se obtiene el nombre del usuario destinatario para retornar un mensaje de éxito
        usuario = conn.execute(text("""
                                    SELECT username
                                    FROM usuarios
                                    WHERE id = :id
                                    """), {"id": compartir_con_id}).fetchone()

    return jsonify({
        "message": f"Archivo compartido con {usuario.username}",
        "success": True
    })


# Ruta para obtener la lista de usuarios con quienes se ha compartido un archivo
@app.route("/archivos/<int:archivo_id>/compartidos", methods=["GET"])
@jwt_required
def obtener_compartidos(archivo_id):
    user_id = request.current_user['user_id']

    with engine.connect() as conn:
        # Comprobar que el archivo pertenece al usuario
        archivo = conn.execute(text("""
                                    SELECT id
                                    FROM archivos
                                    WHERE id = :archivo_id
                                      AND usuario_id = :user_id
                                    """), {"archivo_id": archivo_id, "user_id": user_id}).fetchone()

        if not archivo:
            return jsonify({"error": "Archivo no encontrado o no tienes permisos"}), 404

        # Consultar la lista de usuarios con quienes se ha compartido el archivo
        compartidos = conn.execute(text("""
                                        SELECT u.id, u.username, u.email, ac.fecha_compartido
                                        FROM archivos_compartidos ac
                                                 JOIN usuarios u ON ac.compartido_con_id = u.id
                                        WHERE ac.archivo_id = :archivo_id
                                        ORDER BY ac.fecha_compartido DESC
                                        """), {"archivo_id": archivo_id}).fetchall()

    return jsonify([{
        'id': c.id,
        'username': c.username,
        'email': c.email,
        'fecha_compartido': c.fecha_compartido.isoformat() if c.fecha_compartido else None
    } for c in compartidos])


if __name__ == "__main__":
    # Iniciar la aplicación en el puerto 5000 con soporte SSL
    app.run(host="0.0.0.0", port=5000, ssl_context=("cert.pem", "key.pem"))