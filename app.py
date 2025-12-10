
import os
import re
from datetime import datetime
import pdfplumber

from flask import (
    Flask, render_template, request, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    current_user, logout_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ------------------------------------------------------
# Configuración básica
# ------------------------------------------------------
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = "cambia-esta-clave"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "contratacion.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

UPLOAD_FOLDER = os.path.join(basedir, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ALLOWED_EXTENSIONS = {"pdf"}  # para demo simple

# ------------------------------------------------------
# Estados del proceso (workflow)
# ------------------------------------------------------
ESTADOS_PROCESO = [
    "Recepción H.V",
    "Revisión Tecnología / Reparto",
    "Revisión Abogado (datos básicos)",
    "Solicitud de documentos (correo automático)",
    "Verificación documentos y aceptación",
    "Revisión Área Financiera",
    "Gestión Humana",
    "Elaboración pre-contractual",
    "Solicitud CDP + Validación Jurídica NEA",
    "Solicitud pólizas",
    "Carga al SECOP",
    "Contrato en ejecución",
]

# ------------------------------------------------------
# Modelos
# ------------------------------------------------------
class User(db.Model, UserMixin):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), nullable=False)  # "USUARIO" o "ABOGADO"

    procesos_abogado = db.relationship(
        "ProcesoContratacion",
        back_populates="abogado",
        lazy="dynamic",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class ProcesoContratacion(db.Model):
    __tablename__ = "procesos_contratacion"

    id = db.Column(db.Integer, primary_key=True)

    # Datos básicos del candidato
    nombre_candidato = db.Column(db.String(120), nullable=False)
    telefono = db.Column(db.String(50))
    identificacion = db.Column(db.String(50))
    correo = db.Column(db.String(120))

    cargo = db.Column(db.String(120), nullable=False)
    area = db.Column(db.String(120))

    cv_filename = db.Column(db.String(255))  # archivo almacenado

    estado_index = db.Column(db.Integer, default=0)
    observaciones = db.Column(db.Text)

    abogado_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"))
    abogado = db.relationship("User", back_populates="procesos_abogado")

    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_actualizacion = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def estado_actual(self) -> str:
        try:
            return ESTADOS_PROCESO[self.estado_index]
        except IndexError:
            return "Desconocido"

    def puede_avanzar(self) -> bool:
        return self.estado_index < len(ESTADOS_PROCESO) - 1

    def puede_retroceder(self) -> bool:
        return self.estado_index > 0


# ------------------------------------------------------
# Utilidades
# ------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def extraer_datos_basicos(texto: str) -> dict:
    # Separamos por líneas y limpiamos espacios
    lineas = [l.strip() for l in texto.splitlines() if l.strip()]

    nombre = ""
    correo = ""
    telefono = ""
    identificacion = ""

    # 1) Nombre: primera línea "bonita" que no tenga @ ni links
    for l in lineas:
        low = l.lower()
        if "@" not in low and "linkedin.com" not in low and "www." not in low:
            nombre = l
            break

    # 2) Correo y teléfono: buscamos la línea donde aparezca el correo
    for l in lineas:
        if "@" in l:
            # correo
            m_correo = re.search(r'[\w\.-]+@[\w\.-]+', l)
            if m_correo:
                correo = m_correo.group(0)

            # teléfono (aceptamos +, espacios, guiones, puntos, paréntesis)
            m_tel = re.search(r'(\+?\d[\d\s\-\.\(\)]{7,})', l)
            if m_tel:
                telefono_raw = m_tel.group(1).strip()
                # opcional: normalizar (quitar puntos y espacios)
                telefono = re.sub(r'[^\d+]', '', telefono_raw)
            break

    # 3) Identificación: buscamos patrones típicos (CC, Cédula, Identificación)
        patrones_id = [
            r'\bCC[:\s\-]*([\d\.]+)',
            r'C[ .]?C[ .]?\s*[:\-]?\s*([\d\.]+)',
            r'c[eé]dula\s*(de ciudadanía)?\s*[:\-]?\s*([\d\.]+)',
            r'Identificaci[oó]n\s*[:\-]?\s*([\d\.]+)',
        ]
    for patron in patrones_id:
        m = re.search(patron, texto, flags=re.IGNORECASE)
        if m:
            # tomamos el último grupo que tenga dígitos
            for g in m.groups()[::-1]:
                if g and any(ch.isdigit() for ch in g):
                    identificacion = re.sub(r'\D', '', g)  # solo números
                    break
            if identificacion:
                break

    return {
        "nombre_candidato": nombre,
        "telefono": telefono,
        "correo": correo,
        "identificacion": identificacion,
    }



def asignar_abogado_por_carga():
    abogados = User.query.filter_by(rol="ABOGADO").all()
    if not abogados:
        return None

    indice_estado_final = len(ESTADOS_PROCESO) - 1
    cargas = []
    for a in abogados:
        abiertos = ProcesoContratacion.query.filter(
            ProcesoContratacion.abogado_id == a.id,
            ProcesoContratacion.estado_index < indice_estado_final,
        ).count()
        cargas.append((a, abiertos))

    min_carga = min(c for _, c in cargas)
    candidatos = [a for a, c in cargas if c == min_carga]

    import random
    return random.choice(candidatos) if candidatos else None


# ------------------------------------------------------
# Rutas: autenticación
# ------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Inicio de sesión correcto.", "success")
            return redirect(url_for("index"))
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("login"))


@app.route("/crear_usuarios_demo")
def crear_usuarios_demo():
    """Ruta rápida para crear usuarios de prueba.
       IMPORTANTE: eliminar en producción.
    """
    if User.query.count() == 0:
        coord = User(username="coordinador", rol="USUARIO")
        coord.set_password("1234")
        db.session.add(coord)

        for i in range(1, 4):
            ab = User(username=f"abogado{i}", rol="ABOGADO")
            ab.set_password("1234")
            db.session.add(ab)

        db.session.commit()
        return "Usuarios demo creados: coordinador / abogado1 / abogado2 / abogado3 (clave: 1234)"
    return "Ya existen usuarios en la base de datos."


# ------------------------------------------------------
# Rutas principales
# ------------------------------------------------------
@app.route("/")
@login_required
def index():
    if current_user.rol == "ABOGADO":
        procesos = ProcesoContratacion.query.filter_by(
            abogado_id=current_user.id
        ).order_by(ProcesoContratacion.fecha_creacion.desc()).all()
    else:
        procesos = ProcesoContratacion.query.order_by(
            ProcesoContratacion.fecha_creacion.desc()
        ).all()

    return render_template(
        "index.html",
        procesos=procesos,
        ESTADOS=ESTADOS_PROCESO,
    )


@app.route("/mis_casos")
@login_required
def mis_casos():
    if current_user.rol != "ABOGADO":
        flash("Solo los abogados pueden ver esta vista.", "error")
        return redirect(url_for("index"))

    procesos = ProcesoContratacion.query.filter_by(
        abogado_id=current_user.id
    ).order_by(ProcesoContratacion.fecha_creacion.desc()).all()

    return render_template(
        "mis_casos.html",
        procesos=procesos,
        ESTADOS=ESTADOS_PROCESO,
    )


# ------------------------------------------------------
# Carga de hoja de vida
# ------------------------------------------------------
@app.route("/cv/cargar", methods=["GET", "POST"])
@login_required
def cargar_cv():
    if current_user.rol != "USUARIO":
        flash("Solo usuarios autorizados pueden cargar hojas de vida.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        file = request.files.get("cv")
        cargo = request.form.get("cargo")
        area = request.form.get("area")

        if not file or file.filename == "":
            flash("Debes seleccionar un archivo.", "error")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("Tipo de archivo no permitido. Usa .txt para el demo.", "error")
            return redirect(request.url)

        if not cargo:
            flash("Debes indicar el cargo al que aplica.", "error")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        ruta_guardado = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(ruta_guardado)

        
        with pdfplumber.open(ruta_guardado) as pdf:
            texto = ""
            for page in pdf.pages:
             page_text = page.extract_text() or ""
             texto += page_text + "\n"

             datos = extraer_datos_basicos(texto)

        return render_template(
            "confirmar_datos_cv.html",
            cv_filename=filename,
            datos=datos,
            cargo=cargo,
            area=area,
        )

    return render_template("cargar_cv.html")


@app.route("/cv/confirmar", methods=["POST"])
@login_required
def confirmar_cv():
    if current_user.rol != "USUARIO":
        flash("No estás autorizado para crear procesos desde CV.", "error")
        return redirect(url_for("index"))

    cv_filename = request.form.get("cv_filename")
    nombre = request.form.get("nombre_candidato")
    telefono = request.form.get("telefono")
    identificacion = request.form.get("identificacion")
    correo = request.form.get("correo")
    cargo = request.form.get("cargo")
    area = request.form.get("area")

    if not nombre or not cargo:
        flash("Nombre del candidato y cargo son obligatorios.", "error")
        return redirect(url_for("cargar_cv"))

    abogado_asignado = asignar_abogado_por_carga()
    if not abogado_asignado:
        flash("No hay abogados configurados en el sistema.", "error")
        return redirect(url_for("cargar_cv"))

    proceso = ProcesoContratacion(
        nombre_candidato=nombre,
        telefono=telefono,
        identificacion=identificacion,
        correo=correo,
        cargo=cargo,
        area=area,
        cv_filename=cv_filename,
        abogado=abogado_asignado,
        estado_index=0,
    )
    db.session.add(proceso)
    db.session.commit()

    flash(
        f"Proceso creado y asignado al abogado: {abogado_asignado.username}",
        "success",
    )
    return redirect(url_for("detalle_proceso", proceso_id=proceso.id))


# ------------------------------------------------------
# Detalle de proceso y avance del flujo
# ------------------------------------------------------
@app.route("/proceso/<int:proceso_id>")
@login_required
def detalle_proceso(proceso_id):
    proceso = ProcesoContratacion.query.get_or_404(proceso_id)

    if current_user.rol == "ABOGADO" and proceso.abogado_id != current_user.id:
        flash("No puedes ver procesos asignados a otro abogado.", "error")
        return redirect(url_for("index"))

    return render_template(
        "detalle_proceso.html",
        proceso=proceso,
        ESTADOS=ESTADOS_PROCESO,
    )


@app.route("/proceso/<int:proceso_id>/avanzar", methods=["POST"])
@login_required
def avanzar_proceso(proceso_id):
    proceso = ProcesoContratacion.query.get_or_404(proceso_id)

    if current_user.rol == "ABOGADO" and proceso.abogado_id != current_user.id:
        flash("No puedes modificar procesos asignados a otro abogado.", "error")
        return redirect(url_for("index"))

    if proceso.puede_avanzar():
        proceso.estado_index += 1
        obs = request.form.get("observaciones")
        if obs:
            marca_tiempo = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            nuevo = f"[{marca_tiempo}] {current_user.username}: {obs}"
            if proceso.observaciones:
                proceso.observaciones += "\\n" + nuevo
            else:
                proceso.observaciones = nuevo
        db.session.commit()
        flash("El proceso avanzó a la siguiente etapa.", "success")
    else:
        flash("El proceso ya está en la última etapa.", "info")

    return redirect(url_for("detalle_proceso", proceso_id=proceso.id))


@app.route("/proceso/<int:proceso_id>/retroceder", methods=["POST"])
@login_required
def retroceder_proceso(proceso_id):
    proceso = ProcesoContratacion.query.get_or_404(proceso_id)

    if current_user.rol == "ABOGADO" and proceso.abogado_id != current_user.id:
        flash("No puedes modificar procesos asignados a otro abogado.", "error")
        return redirect(url_for("index"))

    if proceso.puede_retroceder():
        proceso.estado_index -= 1
        db.session.commit()
        flash("El proceso regresó a la etapa anterior.", "warning")
    else:
        flash("El proceso ya está en la primera etapa.", "info")

    return redirect(url_for("detalle_proceso", proceso_id=proceso.id))


# ------------------------------------------------------
# Main
# ------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
