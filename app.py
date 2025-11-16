import os
import smtplib
from email.message import EmailMessage
import secrets
import string
from datetime import timedelta

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv


# ===============================
# CONFIGURACIÓN BÁSICA
# ===============================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "cambia-esta-clave")
app.permanent_session_lifetime = timedelta(hours=4)


# ===============================
# CONEXIÓN A POSTGRES
# ===============================
def get_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME", "DB_universidad"),
        user=os.getenv("DB_USER", "backend_app"),
        password=os.getenv("DB_PASSWORD", "Backend123"),
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        cursor_factory=RealDictCursor,
    )


# ===============================
# FUNCIONES AUXILIARES
# ===============================
def current_user():
    if "user_id" not in session:
        return None
    return {
        "id_usuario": session.get("user_id"),
        "nombre_usuario": session.get("username"),
        "correo_electronico": session.get("email"),
        "roles": session.get("roles", []),
        "rol_actual": session.get("rol_actual"),
    }


def login_required(view_func):
    from functools import wraps

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Debes iniciar sesión primero.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def send_email(to_email, subject, body):
    server = os.getenv("MAIL_SERVER")
    port = int(os.getenv("MAIL_PORT", "587"))
    use_tls = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
    username = os.getenv("MAIL_USERNAME")
    password = os.getenv("MAIL_PASSWORD")
    default_sender = os.getenv("MAIL_DEFAULT_SENDER", username)

    if not (server and port and username and password):
        print("⚠️ No se pudo enviar correo, configuración incompleta.")
        return

    msg = EmailMessage()
    msg["From"] = default_sender
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(server, port) as smtp:
        if use_tls:
            smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)


def generate_random_password(length=10):
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


# Mapa de rol → dashboard
ROLE_DASHBOARD_MAP = {
    "Administrador": "perfil_administrador",
    "Coordinador": "perfil_coordinador",
    "Docente": "perfil_docente",
    "Bibliotecario": "perfil_bibliotecario",
    "Estudiante": "est_perfil_informacion",
}


# ===============================
# LOGIN / LOGOUT
# ===============================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    identificador = request.form.get("identificador", "").strip()
    contrasena = request.form.get("contrasena", "").strip()
    selected_role = request.form.get("rol", "").strip()

    if not identificador or not contrasena:
        flash("Debes llenar usuario/correo y contraseña.", "danger")
        return render_template("login.html")

    if not selected_role or selected_role == "Selecciona tu rol":
        flash("Debes seleccionar tu rol.", "danger")
        return render_template("login.html")

    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT u.id_usuario, u.nombre_usuario, u.correo_electronico,
                   ARRAY_AGG(r.nombre_rol) AS roles
            FROM seguridad.usuarios u
            LEFT JOIN seguridad.usuario_rol ur ON ur.id_usuario = u.id_usuario
            LEFT JOIN seguridad.roles r ON r.id_rol = ur.id_rol
            WHERE u.activo = TRUE
            AND (LOWER(u.nombre_usuario)=LOWER(%s)
                 OR LOWER(u.correo_electronico)=LOWER(%s))
            AND u.contrasena_hash = crypt(%s, u.contrasena_hash)
            GROUP BY u.id_usuario
        """, (identificador, identificador, contrasena))

        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            flash("Credenciales incorrectas.", "danger")
            return render_template("login.html")

        roles_usuario = user["roles"] or []

        if selected_role not in roles_usuario:
            flash("El rol no corresponde a tu cuenta.", "danger")
            return render_template("login.html")

        session.clear()
        session.permanent = True
        session["user_id"] = user["id_usuario"]
        session["username"] = user["nombre_usuario"]
        session["email"] = user["correo_electronico"]
        session["roles"] = roles_usuario
        session["rol_actual"] = selected_role

        endpoint = ROLE_DASHBOARD_MAP.get(selected_role)
        return redirect(url_for(endpoint))

    except Exception as e:
        if conn:
            conn.close()
        flash(f"Error al iniciar sesión: {e}", "danger")
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("login"))


# ===============================
# DASHBOARD GENERAL
# ===============================
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    rol_actual = session.get("rol_actual")

    if not rol_actual:
        roles = user["roles"]
        if roles:
            rol_actual = roles[0]
            session["rol_actual"] = rol_actual

    endpoint = ROLE_DASHBOARD_MAP.get(rol_actual)
    if endpoint:
        return redirect(url_for(endpoint))

    return render_template("dashboard_estudiante.html", user=user)


# ===============================
# PERFILES BASE
# ===============================


@app.route("/perfil/admin")
@login_required
def perfil_administrador():
    user = current_user()
    return render_template("perfiles/profile_admin.html", user=user)


@app.route("/perfil/docente")
@login_required
def perfil_docente():
    user = current_user()
    return render_template("perfiles/profile_docente.html", user=user)


@app.route("/perfil/bibliotecario")
@login_required
def perfil_bibliotecario():
    user = current_user()
    return render_template("perfiles/profile_bibliotecario.html", user=user)


@app.route("/perfil/coordinador")
@login_required
def perfil_coordinador():
    user = current_user()
    return render_template("perfiles/profile_coordinador.html", user=user)


@app.route("/estudiante/informacion")
@login_required
def est_perfil_informacion():
    user = current_user()
    conn = None
    datos = {}
    materias = []
    aulas = []
    biblioteca = []

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT a.numero_control, a.nombre, a.apellido_paterno, a.apellido_materno,
                   c.correo_institucional, c.correo_personal, c.telefono, c.direccion
              FROM seguridad.auth_user_alumno ua
              JOIN academico.alumnos a ON a.numero_control = ua.numero_control
              LEFT JOIN academico.contacto c ON c.numero_control = a.numero_control
             WHERE ua.user_id = %s
            """,
            (user["id_usuario"],),
        )
        datos = cur.fetchone() or {}

        cur.execute(
            """
            SELECT m.clave, m.nombre, cm.semestre, ma.ciclo
              FROM academico.alumno_inscripcion ai
              JOIN planes.materia_alta ma ON ma.materia_alta_id = ai.fk_materia_alta
              JOIN planes.carrera_materia cm ON cm.carrera_materia_id = ma.carrera_materia_id
              JOIN planes.materia m ON m.materia_id = cm.materia_id
             WHERE ai.fk_alumno = (
                 SELECT numero_control FROM seguridad.auth_user_alumno WHERE user_id = %s
             )
             ORDER BY ma.ciclo DESC, m.clave
            """,
            (user["id_usuario"],),
        )
        materias = cur.fetchall()

        cur.execute(
            """
            SELECT a.clave, e.nombre AS edificio, a.piso, ta.nombre AS tipo
              FROM infraestructura.aula a
              JOIN infraestructura.edificio e ON e.edificio_id = a.edificio_id
              JOIN infraestructura.tipo_aula ta ON ta.tipo_id = a.tipo_id
             ORDER BY e.numero, a.clave
            """,
        )
        aulas = cur.fetchall()

        cur.execute(
            """
            SELECT p.id_prestamo, l.titulo_libro, p.estado, p.fecha_devolucion_estimada
              FROM biblioteca.prestamos p
              JOIN biblioteca.libros l ON l.id_libro = p.id_libro
             WHERE p.fk_alumno = (
                 SELECT numero_control FROM seguridad.auth_user_alumno WHERE user_id = %s
             )
             ORDER BY p.id_prestamo DESC
            """,
            (user["id_usuario"],),
        )
        biblioteca = cur.fetchall()

        cur.close()
        conn.close()

    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"No se pudo cargar información del estudiante: {e}", "danger")

    return render_template(
        "perfiles/profile_estudiante.html",
        user=user,
        datos=datos,
        materias=materias,
        aulas=aulas,
        biblioteca=biblioteca,
    )
@app.route("/docente/grupos-materias")
@login_required
def docente_grupos_materias():
    user = current_user()
    docente_id = user["id_usuario"]
    conn = None
    grupos = []

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                ma.materia_alta_id,
                m.clave AS clave_materia,
                m.nombre AS nombre_materia,
                c.nombre AS carrera,
                cm.semestre,
                COALESCE(a.clave, '-') AS aula,
                ma.fk_personal
            FROM planes.materia_alta ma
            JOIN planes.carrera_materia cm
                ON cm.carrera_materia_id = ma.carrera_materia_id
            JOIN planes.materia m
                ON m.materia_id = cm.materia_id
            JOIN planes.carrera c
                ON c.carrera_id = cm.carrera_id
            LEFT JOIN infraestructura.horario_asignacion h
                ON h.fk_materia_alta = ma.materia_alta_id
            LEFT JOIN infraestructura.aula a
                ON a.aula_id = h.fk_aula
            WHERE ma.fk_personal = %s
            ORDER BY c.nombre, m.clave;
            """,
            (docente_id,),
        )
        grupos = cur.fetchall()

        cur.close()
        conn.close()

    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"Error cargando grupos del docente: {e}", "danger")

    return render_template(
        "docente/grupos_materias.html",
        user=user,
        grupos=grupos
    )


# ===============================
# DOCENTE – EVALUACIONES
# ===============================

@app.route("/docente/evaluaciones")
@login_required
def docente_evaluaciones():
    user = current_user()
    docente_id = user["id_usuario"]
    datos = []
    conn = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                ai.id_inscripcion,
                a.numero_control,
                TRIM(a.nombre || ' ' || a.apellido_paterno || ' ' || COALESCE(a.apellido_materno,'')) AS alumno,
                m.clave AS clave_materia,
                m.nombre AS nombre_materia,
                ai.calificacion
            FROM academico.alumno_inscripcion ai
            JOIN academico.alumnos a ON a.numero_control = ai.fk_alumno
            JOIN planes.materia_alta ma ON ma.materia_alta_id = ai.fk_materia_alta
            JOIN planes.carrera_materia cm ON cm.carrera_materia_id = ma.carrera_materia_id
            JOIN planes.materia m ON m.materia_id = cm.materia_id
            WHERE ma.fk_personal = %s
            ORDER BY m.clave, alumno;
            """,
            (docente_id,),
        )
        datos = cur.fetchall()

        cur.close()
        conn.close()

    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"Error cargando evaluaciones: {e}", "danger")

    return render_template(
        "docente/evaluaciones.html",
        user=user,
        datos=datos
    )


@app.route("/docente/evaluaciones/actualizar", methods=["POST"])
@login_required
def docente_actualizar_calificacion():
    user = current_user()
    calificacion = request.form.get("calificacion")
    inscripcion_id = request.form.get("id_inscripcion")

    if not calificacion or not inscripcion_id:
        flash("Datos incompletos.", "danger")
        return redirect(url_for("docente_evaluaciones"))

    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE academico.alumno_inscripcion
               SET calificacion = %s
             WHERE id_inscripcion = %s;
            """,
            (calificacion, inscripcion_id),
        )

        conn.commit()
        cur.close()
        conn.close()

        flash("Calificación actualizada.", "success")

    except Exception as e:
        if conn and not conn.closed:
            conn.rollback()
            conn.close()
        flash(f"Error actualizando calificación: {e}", "danger")

    return redirect(url_for("docente_evaluaciones"))


# ===============================
# DOCENTE – ASISTENCIAS
# ===============================

@app.route("/docente/asistencias")
@login_required
def docente_asistencias():
    user = current_user()
    docente_id = user["id_usuario"]
    grupos = []
    alumnos = []
    materia_alta = request.args.get("materia")

    conn = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        # Obtener grupos del docente
        cur.execute(
            """
            SELECT
                ma.materia_alta_id,
                m.clave,
                m.nombre
            FROM planes.materia_alta ma
            JOIN planes.carrera_materia cm
                ON cm.carrera_materia_id = ma.carrera_materia_id
            JOIN planes.materia m
                ON m.materia_id = cm.materia_id
            WHERE ma.fk_personal = %s
            ORDER BY m.clave;
            """,
            (docente_id,),
        )
        grupos = cur.fetchall()

        # Obtener alumnos del grupo seleccionado
        if materia_alta:
            cur.execute(
                """
                SELECT
                    a.numero_control,
                    TRIM(a.nombre || ' ' || a.apellido_paterno || ' ' || COALESCE(a.apellido_materno,'')) AS alumno
                FROM academico.alumno_inscripcion ai
                JOIN academico.alumnos a ON a.numero_control = ai.fk_alumno
                WHERE ai.fk_materia_alta = %s
                ORDER BY alumno;
                """,
                (materia_alta,),
            )
            alumnos = cur.fetchall()

        cur.close()
        conn.close()

    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"Error cargando asistencias: {e}", "danger")

    return render_template(
        "docente/asistencias.html",
        user=user,
        grupos=grupos,
        alumnos=alumnos,
        materia_alta=materia_alta
    )


# ===============================
# DOCENTE – COMUNICACIÓN
# ===============================

@app.route("/docente/comunicacion")
@login_required
def docente_comunicacion():
    user = current_user()
    avisos = []
    conn = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT id_aviso, titulo, mensaje, fecha
            FROM comunicacion.avisos
            ORDER BY fecha DESC
            LIMIT 50;
            """
        )
        avisos = cur.fetchall()

        cur.close()
        conn.close()

    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"Error cargando avisos: {e}", "danger")

    return render_template(
        "docente/comunicacion.html",
        user=user,
        avisos=avisos
    )


# ===============================
# ADMINISTRADOR – USUARIOS
# ===============================


@app.route("/admin/usuarios")
@login_required
def admin_usuarios():
    user = current_user()
    conn = None
    usuarios = []

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT u.id_usuario, u.nombre_usuario, u.correo_electronico, u.activo,
                   ARRAY_REMOVE(ARRAY_AGG(DISTINCT r.nombre_rol), NULL) AS roles
              FROM seguridad.usuarios u
              LEFT JOIN seguridad.usuario_rol ur ON ur.id_usuario = u.id_usuario
              LEFT JOIN seguridad.roles r ON r.id_rol = ur.id_rol
             GROUP BY u.id_usuario
             ORDER BY u.nombre_usuario;
            """
        )
        usuarios = cur.fetchall()

        cur.close()
        conn.close()

    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"No se pudo cargar el catálogo de usuarios: {e}", "danger")

    return render_template("admin/usuarios_list.html", user=user, usuarios=usuarios)


@app.route("/admin/usuarios/nuevo", methods=["GET", "POST"])
@login_required
def admin_usuario_nuevo():
    user = current_user()
    conn = None
    roles = []

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id_rol, nombre_rol FROM seguridad.roles ORDER BY nombre_rol;")
        roles = cur.fetchall()
        cur.close()
        conn.close()
    except Exception:
        if conn and not conn.closed:
            conn.close()

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        rol_id = request.form.get("rol_id")

        if not (username and email and password and rol_id):
            flash("Completa todos los campos.", "danger")
            return redirect(url_for("admin_usuario_nuevo"))

        conn = None
        try:
            conn = get_connection()
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO seguridad.usuarios(nombre_usuario, correo_electronico, contrasena_hash)
                VALUES (%s, %s, crypt(%s, gen_salt('bf')))
                RETURNING id_usuario;
                """,
                (username, email, password),
            )
            nuevo_id = cur.fetchone()["id_usuario"]

            cur.execute(
                "INSERT INTO seguridad.usuario_rol(id_usuario, id_rol) VALUES (%s, %s);",
                (nuevo_id, rol_id),
            )

            conn.commit()
            cur.close()
            conn.close()

            flash("Usuario creado correctamente.", "success")
            return redirect(url_for("admin_usuarios"))

        except Exception as e:
            if conn and not conn.closed:
                conn.rollback()
                conn.close()
            flash(f"No se pudo crear el usuario: {e}", "danger")

    return render_template("admin/usuario_form.html", user=user, roles=roles, modo="nuevo")


@app.route("/admin/usuarios/<int:id_usuario>/editar", methods=["GET", "POST"])
@login_required
def admin_usuario_editar(id_usuario):
    user = current_user()
    conn = None
    roles = []
    usuario = None

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id_rol, nombre_rol FROM seguridad.roles ORDER BY nombre_rol;")
        roles = cur.fetchall()

        cur.execute(
            "SELECT id_usuario, nombre_usuario, correo_electronico, activo FROM seguridad.usuarios WHERE id_usuario=%s;",
            (id_usuario,),
        )
        usuario = cur.fetchone()

        cur.execute(
            "SELECT id_rol FROM seguridad.usuario_rol WHERE id_usuario=%s;",
            (id_usuario,),
        )
        rol_actual = cur.fetchone()
        if usuario:
            usuario["rol_id"] = rol_actual["id_rol"] if rol_actual else None

        cur.close()
        conn.close()

    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"No se pudo cargar el usuario: {e}", "danger")

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        rol_id = request.form.get("rol_id")

        if not (email and rol_id):
            flash("Correo y rol son obligatorios.", "danger")
            return redirect(url_for("admin_usuario_editar", id_usuario=id_usuario))

        conn = None
        try:
            conn = get_connection()
            cur = conn.cursor()

            if password:
                cur.execute(
                    "UPDATE seguridad.usuarios SET correo_electronico=%s, contrasena_hash=crypt(%s, gen_salt('bf')) WHERE id_usuario=%s;",
                    (email, password, id_usuario),
                )
            else:
                cur.execute(
                    "UPDATE seguridad.usuarios SET correo_electronico=%s WHERE id_usuario=%s;",
                    (email, id_usuario),
                )

            cur.execute(
                "DELETE FROM seguridad.usuario_rol WHERE id_usuario=%s;",
                (id_usuario,),
            )
            cur.execute(
                "INSERT INTO seguridad.usuario_rol(id_usuario, id_rol) VALUES (%s, %s);",
                (id_usuario, rol_id),
            )

            conn.commit()
            cur.close()
            conn.close()

            flash("Usuario actualizado.", "success")
            return redirect(url_for("admin_usuarios"))

        except Exception as e:
            if conn and not conn.closed:
                conn.rollback()
                conn.close()
            flash(f"No se pudo actualizar el usuario: {e}", "danger")

    return render_template(
        "admin/usuario_form.html",
        user=user,
        roles=roles,
        usuario=usuario,
        modo="editar",
    )


@app.route("/admin/usuarios/<int:id_usuario>/bloquear")
@login_required
def admin_usuario_bloquear(id_usuario):
    conn = None
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE seguridad.usuarios SET activo=FALSE WHERE id_usuario=%s;",
            (id_usuario,),
        )
        conn.commit()
        cur.close()
        conn.close()
        flash("Usuario bloqueado.", "info")
    except Exception as e:
        if conn and not conn.closed:
            conn.rollback()
            conn.close()
        flash(f"No se pudo bloquear el usuario: {e}", "danger")
    return redirect(url_for("admin_usuarios"))


@app.route("/admin/usuarios/<int:id_usuario>/reset")
@login_required
def admin_usuario_reset(id_usuario):
    conn = None
    nueva = generate_random_password()
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE seguridad.usuarios SET contrasena_hash=crypt(%s, gen_salt('bf')) WHERE id_usuario=%s;",
            (nueva, id_usuario),
        )
        conn.commit()
        cur.close()
        conn.close()
        flash(f"Contraseña restablecida: {nueva}", "success")
    except Exception as e:
        if conn and not conn.closed:
            conn.rollback()
            conn.close()
        flash(f"No se pudo restablecer la contraseña: {e}", "danger")
    return redirect(url_for("admin_usuarios"))


# ===============================
# BIBLIOTECA
# ===============================


@app.route("/biblioteca/catalogo")
@login_required
def biblioteca_catalogo():
    user = current_user()
    conn = None
    libros = []

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT l.id_libro, l.titulo_libro, c.descripcion AS clasificacion,
                   e.nombre_editorial, i.cantidad_disponible
              FROM biblioteca.libros l
              LEFT JOIN biblioteca.clasificaciones c ON c.id_clasificacion = l.id_clasificacion
              LEFT JOIN biblioteca.editoriales e ON e.id_editorial = l.id_editorial
              LEFT JOIN biblioteca.inventario i ON i.id_libro = l.id_libro
             ORDER BY l.titulo_libro;
            """
        )
        libros = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"No se pudo cargar el catálogo: {e}", "danger")

    return render_template("biblioteca/catalogo.html", user=user, libros=libros)


@app.route("/biblioteca/prestamos")
@login_required
def biblioteca_prestamos():
    user = current_user()
    conn = None
    prestamos = []

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT p.id_prestamo, p.fk_alumno, a.nombre || ' ' || a.apellido_paterno AS alumno,
                   l.titulo_libro, p.fecha_devolucion_estimada, p.estado
              FROM biblioteca.prestamos p
              LEFT JOIN academico.alumnos a ON a.numero_control = p.fk_alumno
              JOIN biblioteca.libros l ON l.id_libro = p.id_libro
             WHERE p.estado = 'Activo'
             ORDER BY p.fecha_devolucion_estimada;
            """
        )
        prestamos = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"No se pudo cargar los préstamos: {e}", "danger")

    return render_template("biblioteca/prestamos.html", user=user, prestamos=prestamos)


@app.route("/biblioteca/prestamos/devolver", methods=["POST"])
@login_required
def biblioteca_prestamo_devolver():
    prestamo_id = request.form.get("prestamo_id")
    conn = None
    if not prestamo_id:
        flash("Selecciona un préstamo.", "warning")
        return redirect(url_for("biblioteca_prestamos"))

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE biblioteca.prestamos SET estado='Devuelto', fecha_devolucion_real=NOW() WHERE id_prestamo=%s;",
            (prestamo_id,),
        )
        conn.commit()
        cur.close()
        conn.close()
        flash("Préstamo marcado como devuelto.", "success")
    except Exception as e:
        if conn and not conn.closed:
            conn.rollback()
            conn.close()
        flash(f"No se pudo actualizar el préstamo: {e}", "danger")
    return redirect(url_for("biblioteca_prestamos"))


@app.route("/biblioteca/historial")
@login_required
def biblioteca_historial():
    user = current_user()
    conn = None
    historial = []

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT p.id_prestamo, p.fk_alumno, a.nombre || ' ' || a.apellido_paterno AS alumno,
                   l.titulo_libro, p.fecha_devolucion_estimada, p.fecha_devolucion_real, p.estado
              FROM biblioteca.prestamos p
              LEFT JOIN academico.alumnos a ON a.numero_control = p.fk_alumno
              JOIN biblioteca.libros l ON l.id_libro = p.id_libro
             WHERE p.estado <> 'Activo'
             ORDER BY p.id_prestamo DESC;
            """
        )
        historial = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"No se pudo cargar el historial: {e}", "danger")

    return render_template("biblioteca/historial.html", user=user, historial=historial)


@app.route("/biblioteca/notificaciones")
@login_required
def biblioteca_notificaciones():
    user = current_user()
    avisos = []
    conn = None

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id_aviso, titulo, mensaje, fecha
              FROM comunicacion.avisos
             ORDER BY fecha DESC
             LIMIT 50;
            """
        )
        avisos = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        if conn and not conn.closed:
            conn.close()
        flash(f"No se pudo cargar notificaciones: {e}", "danger")

    return render_template("biblioteca/notificaciones.html", user=user, avisos=avisos)
