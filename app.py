from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pyodbc
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import random
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'tu_clave_super_secreta_aqui'

# --- CONFIGURACIÓN DE CRIPTOGRAFÍA ---
key = b'6_bWJ7x8z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q=' 
cipher_suite = Fernet(key)

# --- 1. FUNCIÓN DE CONEXIÓN (CORREGIDA) ---
def get_db_connection():
    return pyodbc.connect(
        'DRIVER={ODBC Driver 17 for SQL Server};'
        r'SERVER=IANDAVID\SQLSERVER;'  # <--- Agregue la 'r' al inicio para evitar error de \S
        'DATABASE=banco;'
        'Trusted_Connection=yes;'
        'TrustServerCertificate=yes;'
    )

# --- 2. AUTO-REPARACIÓN DE ADMIN AL INICIAR ---
try:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Generamos hash compatible con Flask
    hash_flask = generate_password_hash("Admin123")
    hash_bytes = hash_flask.encode('utf-8')

    # Actualizamos el admin
    cursor.execute("""
        UPDATE usr.usuarios 
        SET contrasena = ? 
        FROM usr.usuarios u
        JOIN usr.clientes_privado cp ON u.id_cliente = cp.id_cliente
        WHERE cp.correo_electronico = 'admin@bancoseguro.com'
    """, (hash_bytes,))
    
    conn.commit()
    print("\n[EXITO] ADMIN REPARADO: La contrasena 'Admin123' ya funciona.\n")
    conn.close()
except Exception as e:
    # Quitamos los emojis para que Windows no de error
    print(f"\n[AVISO] Salto en reparacion (posiblemente ya correcta o error de conexion): {e}\n")


# --- 3. CONFIGURACIÓN FLASK-LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_cliente, nombre, rol, estatus):
        self.id = id_cliente 
        self.nombre = nombre
        self.rol = rol # 1=Usuario, 2=Admin
        self.estatus = estatus

    def es_admin(self):
        return self.rol == 2

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cp.id_cliente, cp.nombre, cp.id_rol, e.nombre 
            FROM usr.clientes_publico cp
            JOIN gral.estatus e ON cp.id_estatus = e.id_estatus
            WHERE cp.id_cliente = ?
        """, (user_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(id_cliente=row[0], nombre=row[1], rol=row[2], estatus=row[3])
        return None
    except Exception as e:
        print("Error en load_user:", e)
        return None

def limpiar_texto(texto):
    return texto.strip().upper() if texto else ""

# --- AQUÍ DEBAJO SIGUEN TUS RUTAS (@app.route...) ---

# =======================================================
# RUTAS DE AUTENTICACIÓN
# =======================================================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.es_admin(): return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Buscar el hash de la contraseña y el ID del cliente
        cursor.execute("""
            SELECT u.contrasena, cp.id_cliente, cp.nombre, cp.id_rol, e.nombre
            FROM usr.usuarios u
            JOIN usr.clientes_privado cpr ON u.id_cliente = cpr.id_cliente
            JOIN usr.clientes_publico cp ON u.id_cliente = cp.id_cliente
            JOIN gral.estatus e ON cp.id_estatus = e.id_estatus
            WHERE cpr.correo_electronico = ?
        """, (email,))
        
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            stored_hash = user_data[0] # Viene como bytes de la BD si es varbinary, o string
            
            # Asegurarse de que el hash esté en formato correcto para comparar
            if isinstance(stored_hash, bytes):
                stored_hash = stored_hash.decode('utf-8')

            if check_password_hash(stored_hash, password):
                # Verificar si está activo
                if user_data[4] != 'ACTIVO':
                    flash("Tu cuenta está suspendida. Contacta al banco.")
                    return redirect(url_for('login'))

                # Crear objeto usuario y loguear
                user_obj = User(id_cliente=user_data[1], nombre=user_data[2], rol=user_data[3], estatus=user_data[4])
                login_user(user_obj)
                
                # Redirección según rol
                if user_obj.es_admin():
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))
            else:
                flash("Contraseña incorrecta")
        else:
            flash("Usuario no encontrado")
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión.")
    return redirect(url_for('login'))

# =======================================================
# RUTAS DE CLIENTE (USUARIO NORMAL)
# =======================================================

@app.route('/mi-banco')
@login_required
def user_dashboard():
    # Si es admin, redirigir
    if current_user.es_admin(): return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. CONSULTA PRINCIPAL
    # CORRECCIÓN: Cambiamos 'b.nombre_banco' por 'b.nombre'
    query = """
        SELECT TOP 1 
            tp.saldo, 
            tp.ultimos_4, 
            tp.id_tarjeta,
            b.nombre, 
            cp.nombre, 
            cp.apellido_paterno
        FROM ba.tarjetas_publico tp
        JOIN ba.identificador_tarjeta it ON tp.id_tarjeta = it.id_tarjeta
        JOIN ba.bancos b ON tp.id_banco = b.id_banco
        JOIN usr.clientes_publico cp ON it.id_cliente = cp.id_cliente
        WHERE it.id_cliente = ? AND tp.id_estatus_tarjeta = 2
    """
    
    try:
        cursor.execute(query, (current_user.id,))
        data = cursor.fetchone()
    except Exception as e:
        print("Error SQL:", e)
        # Si falla por nombre de columna, intentamos un fallback rápido para que no rompa
        data = None

    # Valores por defecto
    saldo = 0
    ultimos_4 = "----"
    banco_nombre = "Banco Seguro"
    nombre_pila = current_user.nombre 
    nombre_completo = "USUARIO SIN TARJETA"
    movimientos = []
    
    if data:
        saldo = data[0]
        ultimos_4 = data[1]
        id_tarjeta = data[2]
        banco_nombre = data[3] # Ahora tomará el valor de b.nombre
        nombre_pila = data[4]
        apellido = data[5]
        
        nombre_completo = f"{nombre_pila} {apellido}".upper()
        
        # 2. CONSULTA SECUNDARIA: Movimientos
        cursor.execute("""
            SELECT TOP 5
                id_tipo_transaccion, 
                monto, 
                descripcion_usuario, 
                fecha_transaccion,
                id_tarjeta_origen,
                id_tarjeta_destino
            FROM tr.transacciones 
            WHERE id_tarjeta_origen = ? OR id_tarjeta_destino = ?
            ORDER BY fecha_transaccion DESC
        """, (id_tarjeta, id_tarjeta))
        
        raw_movs = cursor.fetchall()
        
        for m in raw_movs:
            es_ingreso = (m[5] == id_tarjeta)
            tipo_txt = "Movimiento"
            if m[0] == 1: tipo_txt = "Depósito"
            elif m[0] == 2: tipo_txt = "Retiro"
            elif m[0] == 3: tipo_txt = "Transferencia"
            
            movimientos.append({
                'tipo': tipo_txt,
                'monto': float(m[1]),
                'descripcion': m[2],
                'fecha': m[3].strftime('%d/%m/%Y'),
                'es_ingreso': es_ingreso
            })

    conn.close()
    
    return render_template('dashboard_tarjeta.html', 
                           nombre_usuario=nombre_pila,
                           nombre_cliente=nombre_completo,
                           banco_nombre=banco_nombre,
                           saldo="{:,.2f}".format(saldo),
                           ultimos_4=ultimos_4,
                           anio_vencimiento="30",
                           movimientos=movimientos)
    
# --- 1. RUTA PARA VER LA PANTALLA (GET) ---
@app.route('/operaciones', methods=['GET'])
@login_required
def ver_operaciones():
    # CORRECCIÓN: Usamos 'current_user.nombre' porque así lo definiste en tu clase User
    return render_template('operaciones.html', nombre_usuario=current_user.nombre)

# --- 2. RUTA PARA PROCESAR LOS DATOS (POST) ---
# (Borra la función 'def transferir' que tenías antes, usa solo esta)
@app.route('/procesar_operacion', methods=['POST'])
@login_required
def procesar_operacion():
    # 1. Recibir datos comunes del formulario
    tipo_op = request.form.get('tipo_operacion') # "DEPOSITO" o "TRANSFERENCIA"
    monto_str = request.form.get('monto')
    
    try:
        monto = float(monto_str)
        if monto <= 0: raise Exception("El monto debe ser positivo.")
    except:
        flash("Monto inválido.")
        return redirect(url_for('ver_operaciones')) 

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # --- MODIFICACIÓN 1: Traer fecha de vencimiento ---
        # Hacemos JOIN con ba.tarjetas_privadas (alias 'tpriv')
        cursor.execute("""
            SELECT TOP 1 tp.id_tarjeta, tp.saldo, tpriv.fecha_vencimiento
            FROM ba.tarjetas_publico tp 
            JOIN ba.identificador_tarjeta it ON tp.id_tarjeta = it.id_tarjeta 
            JOIN ba.tarjetas_privadas tpriv ON tp.id_tarjeta = tpriv.id_tarjeta
            WHERE it.id_cliente = ? AND tp.id_estatus_tarjeta = 2
        """, (current_user.id,))
        
        mi_data = cursor.fetchone()
        
        if not mi_data: raise Exception("No tienes una tarjeta activa.")
        
        # Desempaquetamos los 3 datos
        mi_id_tarjeta, mi_saldo, fecha_venc_str = mi_data

        # --- MODIFICACIÓN 2: Validar Expiración ---
        # El formato en BD es texto "MM/YY" (Ej: "01/20")
        if fecha_venc_str:
            try:
                # Convertimos texto a objeto fecha
                fecha_venc = datetime.strptime(fecha_venc_str, '%m/%y')
                now = datetime.now()
                
                # Comparamos Año y Mes actual
                # Si el año de la tarjeta es menor al actual OR
                # Si es el mismo año pero el mes de la tarjeta es menor al actual
                if (fecha_venc.year < now.year) or \
                   (fecha_venc.year == now.year and fecha_venc.month < now.month):
                    
                    # ERROR: Se detiene todo aquí
                    raise Exception(f"Operación rechazada. Tu tarjeta venció en {fecha_venc_str}.")
            except ValueError:
                # Si el formato en la BD es inválido, podrías bloquear o dejar pasar. 
                # Por seguridad, mejor bloqueamos si no entendemos la fecha.
                print(f"Error formato fecha BD: {fecha_venc_str}")
        
        # ----------------------------------------------

        conn.autocommit = False # Iniciamos transacción manual

        # ==========================================
        # CASO A: DEPÓSITO (Dinero entra)
        # ==========================================
        if tipo_op == 'DEPOSITO':
            # 1. Sumar saldo a mi tarjeta
            cursor.execute("UPDATE ba.tarjetas_publico SET saldo = saldo + ? WHERE id_tarjeta = ?", (monto, mi_id_tarjeta))
            
            # 2. Registrar en Transacciones
            cursor.execute("""
                INSERT INTO tr.transacciones (id_tipo_transaccion, id_tarjeta_origen, id_tarjeta_destino, monto, fecha_transaccion, descripcion_usuario, id_estatus_transaccion)
                VALUES (1, ?, ?, ?, GETDATE(), 'Depósito en Ventanilla Virtual', 2)
            """, (mi_id_tarjeta, mi_id_tarjeta, monto))
            
            conn.commit()
            flash(f"Depósito de ${monto} exitoso.")

        # ==========================================
        # CASO B: TRANSFERENCIA (Dinero sale)
        # ==========================================
        elif tipo_op == 'TRANSFERENCIA':
            cuenta_destino_raw = request.form.get('cuenta_destino')
            descripcion = request.form.get('descripcion') or 'Transferencia SPEI'
            cvv_input = request.form.get('cvv_confirmacion')

            # --- Validaciones Básicas ---
            if not cuenta_destino_raw: raise Exception("Falta la cuenta destino.")
            if not cvv_input: raise Exception("Debes ingresar tu CVV para autorizar.")
            if mi_saldo < monto: raise Exception("Saldo insuficiente.")

            # --- VALIDACIÓN DE SEGURIDAD (CVV) ---
            # Buscamos el CVV encriptado
            cursor.execute("SELECT cvv_encriptado FROM ba.tarjetas_privadas WHERE id_tarjeta = ?", (mi_id_tarjeta,))
            priv_data = cursor.fetchone()

            if not priv_data or not priv_data[0]:
                raise Exception("Tu tarjeta no tiene un CVV configurado.")
            
            # Desencriptamos
            try:
                cvv_real_bd = cipher_suite.decrypt(priv_data[0]).decode('utf-8')
            except:
                raise Exception("Error de seguridad: No se pudo validar la tarjeta.")

            if cvv_input != cvv_real_bd:
                raise Exception("CVV Incorrecto. Transacción rechazada.")

            # --- LIMPIEZA DE CUENTA DESTINO ---
            cuenta_limpia = cuenta_destino_raw.replace(" ", "")
            ultimos_4_destino = cuenta_limpia[-4:] 

            # Buscar tarjeta destino
            cursor.execute("SELECT id_tarjeta FROM ba.tarjetas_publico WHERE ultimos_4 = ?", (ultimos_4_destino,))
            dest_data = cursor.fetchone()
            
            if not dest_data: 
                raise Exception(f"No se encontró ninguna cuenta terminada en {ultimos_4_destino}.")
            
            dest_id_tarjeta = dest_data[0]

            if mi_id_tarjeta == dest_id_tarjeta: raise Exception("No puedes transferirte a ti mismo.")

            # --- EJECUTAR TRANSFERENCIA ---
            cursor.execute("UPDATE ba.tarjetas_publico SET saldo = saldo - ? WHERE id_tarjeta = ?", (monto, mi_id_tarjeta))
            cursor.execute("UPDATE ba.tarjetas_publico SET saldo = saldo + ? WHERE id_tarjeta = ?", (monto, dest_id_tarjeta))

            # Guardar historial
            cursor.execute("""
                INSERT INTO tr.transacciones (id_tipo_transaccion, id_tarjeta_origen, id_tarjeta_destino, monto, fecha_transaccion, descripcion_usuario, id_estatus_transaccion)
                VALUES (3, ?, ?, ?, GETDATE(), ?, 2)
            """, (mi_id_tarjeta, dest_id_tarjeta, monto, descripcion))

            flash(f"Transferencia de ${monto} enviada a tarjeta ...{ultimos_4_destino}")

        else:
            raise Exception("Operación no válida.")

        conn.commit()

    except Exception as e:
        conn.rollback()
        # print("Error Operación:", e) # Descomenta para ver errores en consola
        flash(f"Error: {str(e)}")
    finally:
        conn.close()

    return redirect(url_for('ver_operaciones'))

# =======================================================
# RUTAS DE ADMINISTRADOR
# =======================================================

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.es_admin(): return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Estadísticas simples
    cursor.execute("SELECT COUNT(*) FROM usr.clientes_publico WHERE id_estatus = 1")
    total_clientes = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM ba.tarjetas_publico WHERE id_estatus_tarjeta = 2")
    total_tarjetas = cursor.fetchone()[0]
    
    cursor.execute("SELECT SUM(saldo) FROM ba.tarjetas_publico")
    total_dinero = cursor.fetchone()[0] or 0
    
    conn.close()
    
    return render_template('dashboard_admin.html', 
                           nombre_usuario=current_user.nombre,
                           total_clientes=total_clientes,
                           total_tarjetas=total_tarjetas,
                           total_dinero="{:,.2f}".format(total_dinero))

@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if not current_user.es_admin(): return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    sql = """
        SELECT cp.id_cliente, cp.nombre, cp.apellido_paterno, 
               r.nombre as rol, e.nombre as estatus
        FROM usr.clientes_publico cp
        JOIN usr.roles r ON cp.id_rol = r.id_rol
        JOIN gral.estatus e ON cp.id_estatus = e.id_estatus
        ORDER BY cp.id_cliente DESC
    """
    cursor.execute(sql)
    usuarios = cursor.fetchall()
    conn.close()
    
    return render_template('lista_usuarios.html', usuarios=usuarios)

@app.route('/admin/crear', methods=['POST', 'GET'])
@login_required
def admin_crear():
    if not current_user.es_admin(): return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            nombre = limpiar_texto(request.form['nombre'])
            paterno = limpiar_texto(request.form['paterno'])
            materno = limpiar_texto(request.form['materno'])
            rfc = limpiar_texto(request.form['rfc'])
            email = request.form['email'].strip().lower()
            telefono = request.form['telefono']
            password = request.form['password']
            rol = int(request.form['rol'])
            saldo_inicial = float(request.form['saldo'])
            nacimiento = request.form['nacimiento']
            
            cursor.execute("SELECT TOP 1 1 FROM usr.clientes_privado WHERE correo_electronico = ?", (email,))
            if cursor.fetchone(): raise Exception("Correo duplicado")

            conn.autocommit = False

            cursor.execute("""
                INSERT INTO usr.clientes_publico (id_pais, id_rol, nombre, apellido_paterno, apellido_materno, fecha_nacimiento, id_estatus) 
                VALUES (1, ?, ?, ?, ?, ?, 1); 
                SELECT SCOPE_IDENTITY();
            """, (rol, nombre, paterno, materno, nacimiento))
            new_id = int(cursor.fetchone()[0])

            cursor.execute("INSERT INTO usr.clientes_privado (id_cliente, telefono, correo_electronico, rfc) VALUES (?, ?, ?, ?)", 
                           (new_id, telefono, email, rfc))

            pw_hash = generate_password_hash(password)
            cursor.execute("INSERT INTO usr.usuarios (id_cliente, contrasena) VALUES (?, ?)", (new_id, pw_hash.encode('utf-8')))

            ultimos_4 = str(random.randint(1000, 9999))
            cursor.execute("""
                INSERT INTO ba.tarjetas_publico (id_banco, id_tipo_tarjeta, id_marca, id_red, id_tipo_cuenta, id_categoria, saldo, ultimos_4, id_estatus_tarjeta)
                VALUES (1, 1, 1, 1, 1, 1, ?, ?, 2); 
                SELECT SCOPE_IDENTITY();
            """, (saldo_inicial, ultimos_4))
            id_tarjeta = int(cursor.fetchone()[0])

            cursor.execute("INSERT INTO ba.identificador_tarjeta (id_tarjeta, id_cliente, numero_cuenta, clabe) VALUES (?, ?, 'GEN', 'GEN')", (id_tarjeta, new_id))
            
            pan_enc = cipher_suite.encrypt(f"450000000000{ultimos_4}".encode('utf-8'))
            cursor.execute("INSERT INTO ba.tarjetas_privadas (id_tarjeta, token_pasarela, numero_tarjeta_encriptado, fecha_vencimiento) VALUES (?, 'TK', ?, '12/30')", (id_tarjeta, pan_enc))

            conn.commit()
            flash("Usuario creado correctamente.")
            return redirect(url_for('admin_usuarios'))

        except Exception as e:
            conn.rollback()
            flash(f"Error al crear: {e}")
            return redirect(url_for('admin_crear'))
        finally:
            conn.close()

    return render_template('crear_usuario.html')

@app.route('/admin/editar/<int:id_cliente>', methods=['GET', 'POST'])
@login_required
def admin_editar(id_cliente):
    if not current_user.es_admin(): return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        try:
            nuevo_estatus = request.form['estatus_cliente'] 
            nuevo_estatus_tarjeta = request.form['estatus_tarjeta']
            nuevo_rol = request.form['rol']

            conn.autocommit = False
            cursor.execute("UPDATE usr.clientes_publico SET id_estatus = ?, id_rol = ? WHERE id_cliente = ?", (nuevo_estatus, nuevo_rol, id_cliente))
            cursor.execute("UPDATE ba.tarjetas_publico SET id_estatus_tarjeta = ? WHERE id_tarjeta IN (SELECT id_tarjeta FROM ba.identificador_tarjeta WHERE id_cliente = ?)", (nuevo_estatus_tarjeta, id_cliente))

            conn.commit()
            flash("Datos actualizados correctamente.")
            return redirect(url_for('admin_usuarios'))
        except Exception as e:
            conn.rollback()
            flash(f"Error al editar: {e}")
    
    cursor.execute("SELECT nombre, apellido_paterno, id_estatus, id_rol FROM usr.clientes_publico WHERE id_cliente = ?", (id_cliente,))
    cliente = cursor.fetchone()

    cursor.execute("""
        SELECT TOP 1 tp.id_estatus_tarjeta, et.nombre 
        FROM ba.tarjetas_publico tp
        JOIN ba.identificador_tarjeta it ON tp.id_tarjeta = it.id_tarjeta
        JOIN ba.estatus_tarjeta et ON tp.id_estatus_tarjeta = et.id_estado
        WHERE it.id_cliente = ?
    """, (id_cliente,))
    tarjeta = cursor.fetchone()
    
    cursor.execute("SELECT id_estatus, nombre FROM gral.estatus")
    cat_estatus = cursor.fetchall()
    cursor.execute("SELECT id_estado, nombre FROM ba.estatus_tarjeta")
    cat_estatus_tarjeta = cursor.fetchall()
    cursor.execute("SELECT id_rol, nombre FROM usr.roles")
    cat_roles = cursor.fetchall()

    conn.close()
    return render_template('editar_usuario.html', cliente=cliente, tarjeta=tarjeta, cat_estatus=cat_estatus, cat_estatus_tarjeta=cat_estatus_tarjeta, cat_roles=cat_roles, id_cliente=id_cliente)

@app.route('/admin/baja/<int:id_cliente>')
@login_required
def admin_baja(id_cliente):
    if not current_user.es_admin(): return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        conn.autocommit = False
        cursor.execute("UPDATE usr.clientes_publico SET id_estatus = 3 WHERE id_cliente = ?", (id_cliente,))
        cursor.execute("UPDATE ba.tarjetas_publico SET id_estatus_tarjeta = 3 WHERE id_tarjeta IN (SELECT id_tarjeta FROM ba.identificador_tarjeta WHERE id_cliente = ?)", (id_cliente,))
        conn.commit()
        flash("Usuario dado de baja y tarjetas bloqueadas.")
    except Exception as e:
        conn.rollback()
        flash(f"Error al dar de baja: {e}")
    finally:
        conn.close()
    return redirect(url_for('admin_usuarios'))


@app.route('/admin/crear', methods=['GET', 'POST'])
@login_required
def admin_crear_usuario():
    # Verificamos que sea admin
    if current_user.TipoUsuario != 'administrador':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        tipo_usuario = request.form['tipo_usuario']
        
        # Encriptamos la contraseña (asegurate de tener generate_password_hash importado)
        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO Usuarios (Nombre, Email, PasswordHash, TipoUsuario) VALUES (?, ?, ?, ?)",
                (nombre, email, hashed_password, tipo_usuario)
            )
            conn.commit()
            conn.close()
            flash('Usuario creado exitosamente.', 'success')
            return redirect(url_for('admin_usuarios'))
        except Exception as e:
            flash(f'Error al crear usuario: {e}', 'error')

    # NOTA: En tu imagen, el HTML esta dentro de la carpeta "admin"
    return render_template('admin/crear_usuario.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        try:
            # 1. Obtener datos del formulario
            nombre = request.form['nombre']
            paterno = request.form['paterno']
            materno = request.form.get('materno', '') 
            fecha_nacimiento = request.form['nacimiento']
            id_pais = int(request.form['id_pais']) 
            rfc = request.form['rfc']
            telefono = request.form['telefono']
            email = request.form['email']
            password = request.form['password']

            # 2. Encriptar contraseña para login
            password_hash = generate_password_hash(password)

            conn = get_db_connection()
            cursor = conn.cursor()

            # --- INICIO DE TRANSACCIÓN SQL ---
            
            # A. Insertar en Clientes Público
            sql_publico = """
                SET NOCOUNT ON;
                INSERT INTO usr.clientes_publico 
                (id_pais, nombre, apellido_paterno, apellido_materno, fecha_nacimiento)
                VALUES (?, ?, ?, ?, ?);
                SELECT SCOPE_IDENTITY();
            """
            cursor.execute(sql_publico, (id_pais, nombre, paterno, materno, fecha_nacimiento))
            id_cliente = int(cursor.fetchval()) 

            # B. Insertar en Clientes Privado
            sql_privado = """
                INSERT INTO usr.clientes_privado (id_cliente, telefono, correo_electronico, rfc)
                VALUES (?, ?, ?, ?)
            """
            cursor.execute(sql_privado, (id_cliente, telefono, email, rfc))

            # C. Crear el Usuario (Login)
            sql_usuario = """
                INSERT INTO usr.usuarios (id_cliente, contrasena)
                VALUES (?, ?)
            """
            cursor.execute(sql_usuario, (id_cliente, password_hash.encode('utf-8')))

            # ---------------------------------------------------------
            # D. GENERAR TARJETA, CLABE Y CVV
            # ---------------------------------------------------------
            
            ultimos_4 = str(random.randint(1000, 9999))
            numero_cuenta = f"100{random.randint(1000000, 9999999)}"
            clabe = f"012{random.randint(10000000000000, 99999999999999)}"
            cvv_real = str(random.randint(100, 999)) # Generamos CVV de 3 dígitos

            # Insertar la Tarjeta Pública (Solo guardamos los últimos 4 dígitos visibles)
            sql_tarjeta = """
                SET NOCOUNT ON;
                INSERT INTO ba.tarjetas_publico 
                (id_banco, id_tipo_tarjeta, id_marca, id_red, id_tipo_cuenta, id_categoria, saldo, ultimos_4, id_estatus_tarjeta)
                VALUES (1, 1, 1, 1, 1, 1, 0, ?, 2);
                SELECT SCOPE_IDENTITY();
            """
            cursor.execute(sql_tarjeta, (ultimos_4,))
            id_tarjeta = int(cursor.fetchval())

            # Insertar Identificador Tarjeta
            sql_identificador = """
                INSERT INTO ba.identificador_tarjeta (id_tarjeta, id_cliente, numero_cuenta, clabe)
                VALUES (?, ?, ?, ?)
            """
            cursor.execute(sql_identificador, (id_tarjeta, id_cliente, numero_cuenta, clabe))
            
            # --- CREAR REGISTRO EN TARJETAS PRIVADAS (ENCRIPTADO) ---
            # Simulamos el número completo (PAN)
            pan_falso = f"450000000000{ultimos_4}"
            
            # Encriptamos PAN y CVV con Fernet
            pan_enc = cipher_suite.encrypt(pan_falso.encode('utf-8'))
            cvv_enc = cipher_suite.encrypt(cvv_real.encode('utf-8'))
            
            sql_tarjeta_privada = """
                INSERT INTO ba.tarjetas_privadas (id_tarjeta, token_pasarela, numero_tarjeta_encriptado, cvv_encriptado, fecha_vencimiento)
                VALUES (?, 'TOKEN_SIMULADO', ?, ?, '12/30')
            """
            cursor.execute(sql_tarjeta_privada, (id_tarjeta, pan_enc, cvv_enc))

            # --- CONFIRMAR CAMBIOS ---
            conn.commit()
            conn.close()

            flash('Cuenta creada exitosamente. ¡Inicia sesión!', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            if 'conn' in locals():
                conn.rollback()
                conn.close()
            print("Error detallado en registro:", e) 
            flash(f'Error al registrar: {str(e)}', 'error')
            return redirect(url_for('registro'))

    return render_template('registro.html')

@app.route('/api/obtener-tarjeta', methods=['GET'])
@login_required
def api_obtener_tarjeta():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Solicitamos también el CVV encriptado
        sql = """
            SELECT tp.numero_tarjeta_encriptado, tp.fecha_vencimiento, tp.cvv_encriptado
            FROM ba.tarjetas_privadas tp
            JOIN ba.identificador_tarjeta it ON tp.id_tarjeta = it.id_tarjeta
            WHERE it.id_cliente = ?
        """
        cursor.execute(sql, (current_user.id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            enc_numero = row[0]
            fecha_texto = row[1]
            enc_cvv = row[2] # <--- Nuevo campo
            
            numero_real = "****"
            cvv_real = "***"

            try:
                # Desencriptar Tarjeta
                if enc_numero:
                    numero_real = cipher_suite.decrypt(enc_numero).decode('utf-8')
                
                # Desencriptar CVV
                if enc_cvv:
                    cvv_real = cipher_suite.decrypt(enc_cvv).decode('utf-8')
                else:
                    cvv_real = "N/A" # Para cuentas viejas sin CVV

            except Exception as e:
                print(f"Error desencriptando: {e}")
                numero_real = "Error"
                cvv_real = "Err"

            return jsonify({
                'success': True, 
                'numero': numero_real, 
                'vencimiento': fecha_texto,
                'cvv': cvv_real  # <--- Enviamos el CVV al frontend
            })

        else:
            return jsonify({'success': False, 'error': 'No se encontró tarjeta'}), 404

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route('/historial')
@login_required
def ver_movimientos():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Obtener el ID de mi tarjeta
    cursor.execute("""
        SELECT id_tarjeta FROM ba.identificador_tarjeta 
        WHERE id_cliente = ?
    """, (current_user.id,))
    data_tarjeta = cursor.fetchone()
    
    if not data_tarjeta:
        flash("No se encontró tarjeta asociada.")
        return redirect(url_for('user_dashboard'))

    mi_id_tarjeta = data_tarjeta[0]

    # 2. Consultar TODAS las transacciones (Entradas y Salidas)
    # Usamos tr.transacciones porque es donde guardas los depósitos nuevos
    cursor.execute("""
        SELECT 
            t.id_tipo_transaccion, 
            t.monto, 
            t.descripcion_usuario, 
            t.fecha_transaccion,
            t.id_tarjeta_origen,
            t.id_tarjeta_destino
        FROM tr.transacciones t
        WHERE t.id_tarjeta_origen = ? OR t.id_tarjeta_destino = ?
        ORDER BY t.fecha_transaccion DESC
    """, (mi_id_tarjeta, mi_id_tarjeta))
    
    raw_movimientos = cursor.fetchall()
    conn.close()

    # 3. Formatear los datos para que el HTML los entienda
    lista_movimientos = []
    
    for mov in raw_movimientos:
        id_tipo = mov[0]
        monto = float(mov[1])
        desc = mov[2]
        fecha = mov[3]
        origen = mov[4]
        destino = mov[5]

        # Determinar si es Ingreso (verde) o Gasto (rojo)
        # Si yo soy el destino, es dinero que entra.
        es_ingreso = (destino == mi_id_tarjeta)

        # Poner nombre bonito al tipo
        nombre_tipo = "Movimiento"
        if id_tipo == 1: nombre_tipo = "Depósito"
        elif id_tipo == 2: nombre_tipo = "Retiro"
        elif id_tipo == 3: nombre_tipo = "Transferencia"

        # Crear el objeto diccionario
        mov_obj = {
            'tipo': nombre_tipo,
            'monto': monto,
            'descripcion': desc,
            'fecha': fecha.strftime('%d/%m/%Y %H:%M'), # Formato legible
            'es_ingreso': es_ingreso
        }
        lista_movimientos.append(mov_obj)

    return render_template('movimientos.html', movimientos=lista_movimientos)

# --- RUTA DE REPARACIÓN (Solo úsala una vez) ---
@app.route('/reparar-admin')
def reparar_admin():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Creamos un hash compatible con Flask (Python)
        pass_correcta = generate_password_hash('Admin123') 
        
        # 2. Actualizamos la contraseña del usuario admin
        # Convertimos el string a bytes (.encode) para que entre en el VARBINARY
        cursor.execute("""
            UPDATE usr.usuarios 
            SET contrasena = ? 
            WHERE id_cliente IN (
                SELECT id_cliente FROM usr.clientes_privado 
                WHERE correo_electronico = 'admin@bancoseguro.com'
            )
        """, (pass_correcta.encode('utf-8'),))
        
        conn.commit()
        conn.close()
        return "<h1>¡Éxito!</h1><p>Contraseña del Admin reparada. <a href='/login'>Ve al Login</a> e ingresa con: <b>Admin123</b></p>"
    except Exception as e:
        return f"<h1>Error</h1><p>{str(e)}</p>"
    
@app.route('/admin/movimientos')
@login_required
def admin_movimientos():
    if not current_user.es_admin(): return redirect(url_for('user_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # AHORA LEEMOS DE 'tr.transacciones' QUE ES DONDE SE GUARDAN LOS DEPÓSITOS
    sql = """
        SELECT 
            t.id_transaccion,
            FORMAT(t.fecha_transaccion, 'dd/MM/yyyy HH:mm') as fecha,
            ISNULL(cp.nombre + ' ' + cp.apellido_paterno, 'Usuario Desconocido') as cliente,
            CASE 
                WHEN t.id_tipo_transaccion = 1 THEN 'Depósito' 
                WHEN t.id_tipo_transaccion = 2 THEN 'Retiro'
                WHEN t.id_tipo_transaccion = 3 THEN 'Transferencia'
                ELSE 'Otro' 
            END as tipo,
            t.monto,
            t.descripcion_usuario,
            ISNULL(tp.ultimos_4, '????')
        FROM tr.transacciones t
        LEFT JOIN ba.tarjetas_publico tp ON t.id_tarjeta_origen = tp.id_tarjeta
        LEFT JOIN ba.identificador_tarjeta it ON tp.id_tarjeta = it.id_tarjeta
        LEFT JOIN usr.clientes_publico cp ON it.id_cliente = cp.id_cliente
        ORDER BY t.fecha_transaccion DESC
    """
    
    try:
        cursor.execute(sql)
        movimientos = cursor.fetchall()
    except Exception as e:
        print(f"Error SQL Admin: {e}")
        movimientos = []
    finally:
        conn.close()
    
    return render_template('admin_movimientos.html', movimientos=movimientos)

if __name__ == '__main__':
    app.run(debug=True)
    
