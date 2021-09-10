from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf.csrf import CSRFProtect
import secrets
from dotenv import load_dotenv

# URL DATABASE config=development
dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/col.db"

# Create instance flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(20)
csrf = CSRFProtect(app)

# BASE DE DATOS SQLite config=development
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir

# BASE DE DATOS MySQL config=production
load_dotenv()
# pass_db_admin = os.getenv('DB_ADMIN_KEY')
# app.config["SQLALCHEMY_DATABASE_URI"] = f'mysql+pymysql://root:{pass_db_admin}@localhost/col'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Modelo para crear colaboradores
class User(db.Model):
    __tablename__ = 'colaboradores'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    password = db.Column(db.String(250), unique=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    fecha_inicio_actividad = db.Column(db.String(120), unique=False, nullable=False)
    monto_inicial = db.Column(db.String(120), unique=False, nullable=False)
    fecha_ultima_actualizacion = db.Column(db.String(120), unique=False, nullable=False)
    relacion_registros_colaborador = db.relationship('Record', backref='col', cascade="all, delete")

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_user(username):
        return User.query.get(username)

    def capitalizacion(username, montoMensual):
        i_diaria = 0.000274
        colaborador = User.query.filter(User.username == username).first()
        MontoInicial = float(colaborador.monto_inicial)
        tiempo = int(User.tiempo_de_capitalizacion(username))
        Monto_prefinal = MontoInicial * ((1 + i_diaria)**tiempo)
        if (tiempo == 0 and montoMensual == 0):
            return Monto_prefinal
        elif (tiempo == 0 and montoMensual != 0):
            montoFinal = Monto_prefinal + float(montoMensual)
            return montoFinal
        else:
            Monto_final = Monto_prefinal + float(montoMensual)
            return Monto_final

    def tiempo_de_capitalizacion(username):
        fecha_actual = datetime.now()
        fechaActual = datetime.strftime(fecha_actual, '%d/%m/%Y')
        col = User.query.filter_by(username=username).first()
        if fecha_actual == datetime.strptime(col.fecha_ultima_actualizacion, '%Y-%m-%d'):
            return 0
        else:
            __fechaUltimaActualizacion = datetime.strptime((col.fecha_ultima_actualizacion),'%Y-%m-%d')
            print(__fechaUltimaActualizacion)
            delta = fecha_actual - __fechaUltimaActualizacion
            return delta.days

    def modificarColaborador(username, montoFinal, fechaActual):
        user = User.query.filter(User.username == username).first()
        user.monto_inicial = montoFinal
        user.fecha_ultima_actualizacion = fechaActual
        db.session.add(user)
        db.session.commit()

    def cambiar_password(username, nuevo_password):
        user = User.query.filter(User.username == username).first()
        try:
            password_hashed = User.generate_password_hashed(nuevo_password)
            user.password = password_hashed
            db.session.add(user)
            db.session.commit()
        except:
            pass
    
    def generate_password_hashed(password):
        return generate_password_hash(password)

# Modelo para crear registros de colaboradores
class Record(db.Model):
    __tablename__ = 'registros'
    id = db.Column(db.Integer, primary_key=True)
    colaborador_id = db.Column(db.Integer, db.ForeignKey('colaboradores.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(80), unique=False, nullable=False)
    fecha = db.Column(db.Date, unique=False, nullable=False, index=True)
    monto_mensual = db.Column(db.Integer, unique=False, nullable=False)
    descripcion = db.Column(db.Text())


    def __repr__(self):
        return '<Record %r>' % self.name

    def register(username, montoMensual, conceptoAporte):
        user = User.query.filter_by(username = username).first()
        new_register = Record(
            col = user,
            name = username,
            fecha = datetime.now(),
            monto_mensual = montoMensual,
            descripcion = conceptoAporte
        )
        db.session.add(new_register)
        db.session.commit()

    def filtroDatos(username, fecha1, fecha2):
        listaDatosColaborador = []
        try:
            user1 = Record.query.filter_by(name=username).all()
            user2 = Record.query.filter(Record.name==username).filter(Record.fecha.between(fecha1, fecha2)).all()
            if fecha1 == "" and fecha2 == "":
                if len(user1) == 0:
                    str = "No se encontraron coincidencias en la busqueda."
                    listaDatosColaborador.append((str))
                    return listaDatosColaborador
                else:
                    for i in user1:
                        nombre = i.name
                        fecha = i.fecha
                        monto_mensual = i.monto_mensual
                        descripcion = i.descripcion
                        listaDatosColaborador.append((nombre, fecha, monto_mensual, descripcion))
                    return listaDatosColaborador
            else:
                if len(user2) == 0:
                    str = "No se encontraron coincidencias en la busqueda."
                    listaDatosColaborador.append((str))
                    return listaDatosColaborador
                else:
                    for j in user2:
                        nombre = j.name
                        fecha = j.fecha
                        monto_mensual = j.monto_mensual
                        descripcion = j.descripcion
                        listaDatosColaborador.append((nombre, fecha, monto_mensual, descripcion))
                return listaDatosColaborador
        except:
            str = "No se encontraron coincidencias en la busqueda."
            listaDatosColaborador.append((str))
            return listaDatosColaborador
           
# Clase colaborador + funciones de filtrado de datos 
class Colaborador():
        
    def montoTotal():
        monto_total = 0
        for i in User.query.filter(User.username and User.monto_inicial).all():
            monto_total += float(i.monto_inicial)
        return monto_total

    def dataPush():
        tuplaColaboradores = []
        montoTotal = Colaborador.montoTotal()
        for j in User.query.filter(User.username and User.monto_inicial).all():
            nombre = j.username
            porcentaje = float(j.monto_inicial)/montoTotal
            tuplaColaboradores.append((nombre,porcentaje))
        return tuplaColaboradores

    def data_Filter(username):
        listaDatosColaborador = []
        user1 = Record.query.filter_by(name=username).all().asc()
        for i in user1:
            nombre = i.name
            fecha = i.fecha
            monto_mensual = i.monto_mensual
            descripcion = i.descripcion
            listaDatosColaborador.append((nombre, fecha, monto_mensual, descripcion))
        return listaDatosColaborador


@app.errorhandler(404)
def page_not_found(e):
    return render_template('error/404.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form["username"]).first()
        email = User.query.filter_by(email=request.form["username"]).first()

        if user:
            if check_password_hash(user.password, request.form["password"]):
                if user.is_admin == True:
                    session["username"] = user.username
                    flash("Te has logeado exitosamente!!", "success")
                    return redirect(url_for('inicio'))
                session["username"] = user.username
                flash("Te has logeado exitosamente!!", "success")
                return redirect(url_for('home'))
            
        elif email:
            if check_password_hash(email.password, request.form["password"]):
                if email.is_admin == True:
                    session["username"] = email.username
                    flash("Te has logeado exitosamente!!", "success")
                    return redirect(url_for('inicio'))
                session["username"] = email.username
                flash("Te has logeado exitosamente!!", "success")
                return redirect(url_for('home'))

        flash("Los datos que has ingresado no coinciden con un usuario registrado", "error")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/cambiarPasswordAdmin', methods = ["GET", "POST"])
def cambiar_password_admin():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin == True:
            if request.method == 'POST':
                usuario = request.form['username']
                nuevo_password = request.form['nuevoPassword']
                confirmacion_password = request.form['confirmacionPassword']
                if nuevo_password == confirmacion_password:
                    User.cambiar_password(usuario, nuevo_password)
                    flash("Contraseña del usuario {} cambiada exitosamente!!".format(usuario), "success")
                    return redirect(url_for('inicio'))
                else:
                    flash('las contraseñas no coinciden', "error")
                    return render_template('/cambio_password_admin.html')
            else:
                return render_template('/cambio_password_admin.html')
        elif email.is_admin == True:
            if request.method == 'POST':
                usuario = request.form['username']
                nuevo_password = request.form['nuevoPassword']
                confirmacion_password = request.form['confirmacionPassword']
                if nuevo_password == confirmacion_password:
                    User.cambiar_password(usuario, nuevo_password)
                    flash("Contraseña del usuario {} cambiada exitosamente!!".format(usuario), "success")
                    return redirect(url_for('inicio'))
                else:
                    flash('las contraseñas no coinciden', "error")
                    return render_template('/cambio_password_admin.html')
            else:
                return render_template('/cambio_password_admin.html')
        return "Vista protegida solo para el admin"
    return "Necesitas logearte"

@app.route('/cambiarPassword', methods = ["GET", "POST"])
def cambiar_password():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if request.method == 'POST':
            nuevo_password = request.form['nuevoPassword']
            confirmacion_password = request.form['confirmacionPassword']
            if nuevo_password == confirmacion_password:
                User.cambiar_password(user.username, nuevo_password)
                flash("La contraseña ha sido cambiada exitosamente!!", "success")
                return redirect(url_for('home'))
            else:
                flash('las contraseñas no coinciden', "error")
                return render_template('/cambio_password.html')
        else:
            return render_template('/cambio_password.html')
        
    return "Necesitas logearte"

@app.route('/inicio')
def inicio():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin == True:
            colaboradores = User.query.order_by(User.username).all()
            return render_template('inicio.html', colaboradores=colaboradores)
        elif email.is_admin == True:
            colaboradores = User.query.order_by(User.username).all()
            return render_template('inicio.html', colaboradores=colaboradores)
        return "Vista protegida solo para el admin"
    return "Necesitas logearte primero"

@app.route('/select', methods = ["GET", "POST"])
def select():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin or email.is_admin  == True:
            if request.method == 'POST':
                username = request.form['username']
                fecha1 = request.form['fecha1']
                fecha2 = request.form['fecha2']
                colaborador = User.query.filter_by(username=username).first()
                user_data = Record.filtroDatos(username, fecha1, fecha2)
                print(user_data)
                return render_template('infoCol.html', colaborador = colaborador, user = user_data)
            return "method GET is undefined"
        return "Esta vista pertenece al admin"
    return "Necesitas logearte primero"

@app.route("/signup", methods = ["GET", "POST"])
def signup():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin == True:
            if request.method == "POST":
                hashed_pw = generate_password_hash(request.form["password"], method="sha256")
                new_user = User(
                    username=request.form["username"],
                    email=request.form["email"],
                    password=hashed_pw,
                    fecha_inicio_actividad=request.form["fecha_inicio_actividad"],
                    monto_inicial=request.form["monto_inicial"],
                    fecha_ultima_actualizacion=request.form["fechaUltimaAct"]
                )
                db.session.add(new_user)
                db.session.commit()
                usuario = User.query.filter_by(username=request.form["username"]).first()

                flash("El usuario {} fue registrado".format(request.form["username"]), "error")
                return redirect(url_for('signup'))
            return render_template('signup.html')
        elif email.is_admin == True:
            if request.method == "POST":
                hashed_pw = generate_password_hash(request.form["password"], method="sha256")
                new_user = User(
                    username=request.form["username"],
                    email=request.form["email"],
                    password=hashed_pw,
                    fecha_inicio_actividad=request.form["fecha_inicio_actividad"],
                    monto_inicial=request.form["monto_inicial"],
                    fecha_ultima_actualizacion=request.form["fechaUltimaAct"]
                )
                db.session.add(new_user)
                db.session.commit()

                flash("El usuario {} fue registrado".format(request.form["username"]), "error")
                return redirect(url_for('signup'))

            return render_template('signup.html')
        
        return "Vista protegida solo para el admin"

    return "debes logearte primero"

@app.route("/update")
def update():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin == True:
            return render_template('actualizar.html')
        elif email.is_admin == True:
            return render_template('actualizar.html')
        return "Vista protegida solo para el admin"
    return "Debes Logearte primero"

@app.route("/actualizar", methods = ["GET", "POST"])
def actualizar():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin == True:
            if request.method == "POST":
                username = request.form['username']
                montoMensual = request.form['MontoMensual']
                conceptoAporte = request.form['conceptoAporte']
                colaborador = User.query.filter_by(username=username).first()
                if colaborador:      
                    montoFinal = str(User.capitalizacion(username, montoMensual))
                    fecha_actual = datetime.now()
                    fechaActual = datetime.strftime(fecha_actual, '%Y-%m-%d')
                    User.modificarColaborador(username, montoFinal, fechaActual)
                    Record.register(username, montoMensual, conceptoAporte)
                    flash("El usuario {} fue actualizado".format(request.form["username"]), "success")
                    return redirect(url_for('update'))
                flash("El usuario que intenta actualizar no se encuentra en la base de datos", "error")
                return redirect(url_for('update'))
            return redirect(url_for('update'))
        elif email.is_admin == True:
            if request.method == "POST":
                username = request.form['username']
                montoMensual = request.form['MontoMensual']
                conceptoAporte = request.form['conceptoAporte']
                colaborador = User.query.filter_by(username=username).first()
                if colaborador:      
                    montoFinal = str(User.capitalizacion(username, montoMensual))
                    fecha_actual = datetime.now()
                    fechaActual = datetime.strftime(fecha_actual, '%Y-%m-%d')
                    User.modificarColaborador(username, montoFinal, fechaActual)
                    Record.register(username, montoMensual, conceptoAporte)
                    flash("El usuario {} fue actualizado".format(request.form["username"]), "success")
                    return redirect(url_for('update'))
                flash("El usuario que intenta actualizar no se encuentra en la base de datos", "error")
                return redirect(url_for('update'))
            return redirect(url_for('update'))

        return "Esta vista pertenece al admin, usted no puede ingresar"
    return "Debes Logearte primero"
            
@app.route('/delete')
def delete():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin == True:
            return render_template('eliminar.html')
        elif email.is_admin == True:
            return render_template('eliminar.html')
        return "Vista protegida solo para el admin"
    return "Debes Logearte primero"

@app.route('/eliminar', methods = ["GET", "POST"])
def eliminar():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin == True:
            if request.method == "POST":
                username = request.form['username']
                colaborador = User.query.filter_by(username=username).first()
                user_id = colaborador.id
                if colaborador:
                    db.session.delete(colaborador)
                    db.session.commit()
                    flash("El usuario {} fue eliminado".format(username), "success")
                    return redirect(url_for('delete'))
                flash("El usuario {} no se encuentra en la base de datos".format(username), "success")
                return redirect(url_for('delete'))
            return redirect(url_for('delete'))
        if email.is_admin == True:
            if request.method == "POST":
                username = request.form['username']
                colaborador = User.query.filter_by(username=username).first()
                user_id = colaborador.id
                if colaborador:
                    db.session.delete(colaborador)
                    db.session.commit()
                    flash("El usuario {} fue eliminado".format(username), "success")
                    return redirect(url_for('delete'))
                flash("El usuario {} no se encuentra en la base de datos".format(username), "success")
                return redirect(url_for('delete'))
            return redirect(url_for('delete'))


        return "Esta vista pertenece al admin, usted no puede ingresar"
    return "Debes Logearte primero"

@app.route('/grafica')
def grafica():
    if "username" in session:
        user_name = session["username"]
        email = session["username"]
        user = User.query.filter_by(username=user_name).first()
        email = User.query.filter_by(email=email).first()
        if user.is_admin or email.is_admin  == True:
            num = 19000
            col = Colaborador.dataPush()
            labels = [row[0] for row in col]
            values = [row[1] for row in col]
            return render_template('graficaAdmin.html', labels=labels, values=values, col=col, num=num)
        
        
        return "Esta vista pertenece al admin, usted no puede ingresar"
    return "debes logearte primero"

@app.route('/home')
def home():
    if "username" in session:
        num = 19000
        col = Colaborador.dataPush()
        labels = [row[0] for row in col]
        values = [row[1] for row in col]
        return render_template('home.html', labels=labels, values=values, col=col, num=num)

    return "debes logearte primero"

@app.route('/detalles', methods = ["GET", "POST"])
def detalles():
    if "username" in session:
        if request.method == 'GET':
            user_name = session["username"]
            email = session["username"]
            user1 = User.query.filter_by(username=user_name).first()
            email = User.query.filter_by(email=email).first()
            print(user1)
            if user1 == False:
                nombre = email.username
                user_data = Colaborador.data_Filter(nombre)
            else:
                nombre = user_name
                user_data = Colaborador.data_Filter(nombre)
            return render_template('detalles_colaborador.html', colaborador = user1, dataUser = user_data)
        return "Necesitas iniciar sesion para ver esta vista"
    return "Necesitas logearte primero"

@app.route('/insert/default')
def insert_default():
    admin = User(
        username = "Administracion",
        email = "administracion@simplecomercio.com",
        is_admin = True,
        fecha_inicio_actividad = "01/03/2020",
        monto_inicial = "0",
        fecha_ultima_actualizacion = "0"
    )
    pass_admin = os.getenv('ADMIN_KEY')
    admin.set_password(pass_admin)
    db.session.add(admin)
    db.session.commit()
    flash("El admin fue creado", "success")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    username = session["username"]
    session.pop("username", None)

    flash("Hasta la proxima {}".format(username), "success")
    return render_template('login.html')


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)


