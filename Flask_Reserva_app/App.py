from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from functools import wraps  # Para el decorador login_required
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuración del correo
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'tu_correo@gmail.com'
app.config['MAIL_PASSWORD'] = 'tu_contraseña'
mail = Mail(app)

# Obtener la ruta absoluta del directorio actual
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Crear la ruta completa para la base de datos
DB_PATH = os.path.join(BASE_DIR, 'instance', 'docentes.db')

# Crear la carpeta instance si no existe
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Crear tabla docentes si no existe
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS docentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            correo TEXT UNIQUE NOT NULL,
            clave TEXT NOT NULL,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Crear tabla reservas si no existe
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reservas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            id_usuario INTEGER NOT NULL,
            nombre_docente TEXT NOT NULL,
            sala INTEGER NOT NULL,
            fecha DATE NOT NULL,
            bloque TEXT NOT NULL,
            fecha_reserva TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (id_usuario) REFERENCES docentes(id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Inicializar la base de datos
init_db()

def get_db_connection():
    return sqlite3.connect(DB_PATH)

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        clave = request.form['clave']
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, nombre, clave FROM docentes WHERE correo = ?', (correo,))
        docente = cursor.fetchone()
        
        if docente and check_password_hash(docente[2], clave):
            session['docente_id'] = docente[0]
            session['nombre'] = docente[1]
            session['correo'] = correo
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('index'))
        else:
            flash('Correo o contraseña incorrectos', 'error')
        
        conn.close()
    
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registrar_docente():
    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo'].lower()  # Convertir a minúsculas
        clave = request.form['clave']
        
        # Validar formato del correo
        if not correo.endswith('@intep.edu.co'):
            flash('Debe usar un correo institucional (@intep.edu.co)', 'error')
            return redirect(url_for('registrar_docente'))
        
        # Validar longitud de la contraseña
        if len(clave) < 8:
            flash('La contraseña debe tener al menos 8 caracteres', 'error')
            return redirect(url_for('registrar_docente'))
            
        conn = sqlite3.connect('instance/docentes.db')
        cursor = conn.cursor()
        
        try:
            # Verificar si el correo ya existe
            cursor.execute('SELECT id FROM docentes WHERE correo = ?', (correo,))
            if cursor.fetchone():
                flash('Este correo ya está registrado en el sistema', 'error')
                return redirect(url_for('registrar_docente'))
            
            # Validar que el nombre no esté vacío
            if not nombre.strip():
                flash('El nombre no puede estar vacío', 'error')
                return redirect(url_for('registrar_docente'))
            
            # Crear hash de la contraseña
            hashed_password = generate_password_hash(clave)
            
            # Insertar nuevo docente
            cursor.execute('''
                INSERT INTO docentes (nombre, correo, clave)
                VALUES (?, ?, ?)
            ''', (nombre.strip(), correo, hashed_password))
            
            conn.commit()
            flash('Registro exitoso. Por favor inicie sesión', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            conn.rollback()
            flash('Error al registrar. Por favor intente nuevamente', 'error')
            print(f"Error en registro: {str(e)}")
        finally:
            conn.close()
    
    return render_template('registro.html')

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        correo = request.form['correo']
        
        if not correo.endswith('@intep.edu.co'):
            flash('Debe ingresar un correo institucional (@intep.edu.co)', 'error')
            return redirect(url_for('recuperar_contrasena'))
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id, nombre FROM docentes WHERE correo = ?', (correo,))
            docente = cursor.fetchone()
            
            if docente:
                # Generar nueva contraseña temporal
                nueva_clave = os.urandom(8).hex()
                hashed_password = generate_password_hash(nueva_clave)
                
                # Actualizar contraseña en la base de datos
                cursor.execute('UPDATE docentes SET clave = ? WHERE id = ?', 
                             (hashed_password, docente[0]))
                conn.commit()
                
                # Enviar correo con la nueva contraseña
                msg = Message('Recuperación de Contraseña - INTEP',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[correo])
                msg.body = f'''Hola {docente[1]},
                
Tu nueva contraseña temporal es: {nueva_clave}

Por favor, ingresa al sistema y cambia tu contraseña lo antes posible.

Saludos,
Sistema de Reservas INTEP'''
                
                mail.send(msg)
                flash('Se ha enviado una nueva contraseña a tu correo', 'success')
                return redirect(url_for('login'))
            else:
                flash('El correo ingresado no está registrado', 'error')
                
        except Exception as e:
            print(f"Error en recuperación de contraseña: {str(e)}")
            flash('Error al procesar la solicitud.', 'error')

@app.route('/index', methods=['GET', 'POST'])
def index():
    if 'docente_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if request.method == 'POST':
        sala = request.form['sala']
        fecha = request.form['fecha']
        bloque = request.form['bloque']
        
        # Verificar si la fecha es válida (no anterior a hoy)
        fecha_seleccionada = datetime.strptime(fecha, '%Y-%m-%d').date()
        if fecha_seleccionada < datetime.now().date():
            flash('No se pueden hacer reservas en fechas pasadas', 'error')
            return redirect(url_for('index'))
        
        try:
            # Verificar si el bloque ya está reservado
            cursor.execute('''
                SELECT id FROM reservas 
                WHERE sala = ? AND fecha = ? AND bloque = ?
            ''', (sala, fecha, bloque))
            
            if cursor.fetchone():
                flash('Este bloque ya está reservado', 'error')
            else:
                # Hacer la reserva
                cursor.execute('''
                    INSERT INTO reservas (id_usuario, nombre_docente, sala, fecha, bloque)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session['docente_id'], session['nombre'], sala, fecha, bloque))
                
                conn.commit()
                
                # Enviar correo de confirmación
                try:
                    msg = Message('Confirmación de Reserva - INTEP',
                                sender=app.config['MAIL_USERNAME'],
                                recipients=[session['correo']])
                    
                    msg.body = f'''
                    Hola {session['nombre']},

                    Tu reserva ha sido confirmada:
                    
                    Sala: {sala}
                    Fecha: {fecha}
                    Bloque: {bloque}
                    
                    Saludos,
                    Sistema de Reservas INTEP
                    '''
                    
                    mail.send(msg)
                except Exception as e:
                    print(f"Error enviando correo: {str(e)}")
                
                flash('Reserva realizada con éxito', 'success')
                
        except Exception as e:
            print(f"Error en reserva: {str(e)}")
            flash('Error al procesar la reserva', 'error')
            conn.rollback()
    
    # Obtener bloques ocupados para el calendario
    cursor.execute('SELECT fecha, sala, bloque FROM reservas')
    reservas_ocupadas = cursor.fetchall()
    conn.close()
    
    return render_template('index.html', 
                         reservas_ocupadas=reservas_ocupadas,
                         bloques_horarios=[
                             "7:00 - 9:00",
                             "9:00 - 11:00",
                             "11:00 - 13:00",
                             "14:00 - 16:00",
                             "16:00 - 18:00",
                             "18:00 - 20:00",
                             "20:00 - 22:00"
                         ])

@app.route('/mis_reservas')
def mis_reservas():
    if 'docente_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Esto permite acceder a las columnas por nombre
    cursor = conn.cursor()
    
    # Obtener todas las reservas del docente actual
    cursor.execute('''
        SELECT * FROM reservas 
        WHERE id_usuario = ? 
        ORDER BY fecha ASC, bloque ASC
    ''', (session['docente_id'],))
    
    reservas = cursor.fetchall()
    conn.close()
    
    return render_template('mis_reservas.html', reservas=reservas)

@app.route('/cancelar_reserva/<int:id>', methods=['POST'])
def cancelar_reserva(id):
    if 'docente_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Verificar que la reserva pertenezca al docente
        cursor.execute('SELECT id_usuario FROM reservas WHERE id = ?', (id,))
        reserva = cursor.fetchone()
        
        if reserva and reserva[0] == session['docente_id']:
            cursor.execute('DELETE FROM reservas WHERE id = ?', (id,))
            conn.commit()
            flash('Reserva cancelada exitosamente', 'success')
        else:
            flash('No tienes permiso para cancelar esta reserva', 'error')
            
    except Exception as e:
        print(f"Error cancelando reserva: {str(e)}")
        flash('Error al cancelar la reserva', 'error')
        conn.rollback()
    finally:
        conn.close()
        
    return redirect(url_for('mis_reservas'))

@app.route('/editar_reserva/<int:id>', methods=['GET', 'POST'])
def editar_reserva(id):
    if 'docente_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if request.method == 'POST':
        sala = request.form['sala']
        fecha = request.form['fecha']
        bloque = request.form['bloque']
        
        try:
            # Verificar que la reserva pertenezca al docente
            cursor.execute('SELECT id_usuario FROM reservas WHERE id = ?', (id,))
            reserva = cursor.fetchone()
            
            if reserva and reserva[0] == session['docente_id']:
                # Verificar si el nuevo bloque está disponible
                cursor.execute('''
                    SELECT id FROM reservas 
                    WHERE sala = ? AND fecha = ? AND bloque = ? AND id != ?
                ''', (sala, fecha, bloque, id))
                
                if cursor.fetchone():
                    flash('El bloque seleccionado ya está ocupado', 'error')
                else:
                    cursor.execute('''
                        UPDATE reservas 
                        SET sala = ?, fecha = ?, bloque = ? 
                        WHERE id = ?
                    ''', (sala, fecha, bloque, id))
                    conn.commit()
                    flash('Reserva actualizada exitosamente', 'success')
                    return redirect(url_for('mis_reservas'))
            else:
                flash('No tienes permiso para editar esta reserva', 'error')
                
        except Exception as e:
            print(f"Error editando reserva: {str(e)}")
            flash('Error al actualizar la reserva', 'error')
            conn.rollback()
    
    # Obtener datos de la reserva actual
    cursor.execute('SELECT * FROM reservas WHERE id = ?', (id,))
    reserva = cursor.fetchone()
    conn.close()
    
    if not reserva or reserva[1] != session['docente_id']:
        flash('Reserva no encontrada', 'error')
        return redirect(url_for('mis_reservas'))
        
    return render_template('editar_reserva.html', reserva=reserva)

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión exitosamente', 'success')
    return redirect(url_for('login'))

# Función para verificar si el usuario está autenticado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'docente_id' not in session:
            flash('Por favor inicie sesión para acceder', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/verificar_disponibilidad', methods=['POST'])
def verificar_disponibilidad():
    if 'docente_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401
        
    data = request.get_json()
    fecha = data.get('fecha')
    sala = data.get('sala')
    
    conn = sqlite3.connect('instance/docentes.db')
    cursor = conn.cursor()
    
    # Obtener bloques ocupados
    cursor.execute('''
        SELECT bloque FROM reservas 
        WHERE fecha = ? AND sala = ?
    ''', (fecha, sala))
    
    bloques_ocupados = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        'bloques_ocupados': bloques_ocupados,
        'fecha': fecha,
        'sala': sala
    })

# Agregar esta nueva ruta
@app.route('/admin/reservas')
def admin_reservas():
    if 'docente_id' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('instance/docentes.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            reservas.id,
            reservas.fecha,
            reservas.sala,
            reservas.bloque,
            reservas.fecha_reserva,
            docentes.nombre as nombre_docente,
            docentes.correo as correo_docente
        FROM reservas
        JOIN docentes ON reservas.id_usuario = docentes.id
        ORDER BY reservas.fecha DESC, reservas.bloque ASC
    ''')
    
    reservas = cursor.fetchall()
    conn.close()
    
    today = datetime.now().strftime('%Y-%m-%d')
    
    return render_template('admin/reservas.html', reservas=reservas, today=today)

if __name__ == '__main__':
    init_db()  # Inicializar la base de datos
    app.run(debug=True)
