from flask import Flask, request, render_template, send_file
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
from sqlalchemy import create_engine, text

app = Flask(__name__)
PRIVATE_FOLDER = "private_keys"
os.makedirs(PRIVATE_FOLDER, exist_ok=True)

# Conexión a MySQL
engine = create_engine("mysql+pymysql://diplomado:diplomado@persistencia:3306/persistencia")

@app.route("/", methods=["GET", "POST"])
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

    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)