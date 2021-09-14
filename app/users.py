from os import name
from flask import Flask, config, request, jsonify, make_response
from flask.helpers import url_for
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from sqlalchemy.orm import backref
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)

folder_path = 'imagen\\'
app.config['SECRET_KEY'] = 'thisissecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/bdnueva'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = folder_path

db = SQLAlchemy(app)
ma = Marshmallow(app)

class Usuarios(db.Model):
    idUser = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    addresses = db.relationship('Carrito', backref='usuarios', lazy=True)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password 

class Carrito(db.Model):
    idCarrito = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('usuarios.idUser'), nullable=False)
    modelo = db.Column(db.String(50), nullable=False)
    desc = db.Column(db.String(50), nullable=False)
    imagen = db.Column(db.String(120), nullable=False)

    def __init__(self, UserId, modelo, desc, imagen):
        self.UserId = UserId
        self.modelo = modelo
        self.desc = desc
        self.imagen = imagen

db.create_all()

class CarritoSchema(ma.Schema):
    class Meta:
        fields = ('idCarrito', 'UserId', 'modelo', 'desc', 'imagen')

carrito_schema = CarritoSchema()

carritos_schema = CarritoSchema(many=True)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'mensaje':'falta el tken'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuarios.query.filter_by(idUser=data['Id_del_usuario']).first()
        except:
            return jsonify({'mensaje':'no'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



#POST para registrar un nuevo usuario
@app.route('/register', methods=['POST'])
def newUser():
    data = request.get_json(force=True)
    hashedPassword = generate_password_hash(data['contrasena'], method='md5')

    name = data['nombre']
    email = data['correo']
    
    nuevoUsuario = Usuarios(name, email, password=hashedPassword)
    db.session.add(nuevoUsuario)
    db.session.commit()
    return jsonify({'Mensaje':'Registrado correctamente!'})

#INICIAR SESION
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify(401, {'Error':'Necesitas llenar los campos!!!'}, 401)

    user = Usuarios.query.filter_by(name=auth.username).first()

    if not user:
        return jsonify({'Error':'Usuario no encontrado1'})
    
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'Id_del_usuario': user.idUser, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'Token': token})

    return jsonify({'auth.password':auth.username})

#################################
## CRUD PARA LA TABLA CARRITOS ##
#################################

#GET TODOS LOS DATOS
@app.route('/carritos', methods=['GET'])
def getCarrito():
    allCarritos = Carrito.query.all()
    result = carritos_schema.dump(allCarritos)
    return jsonify(result)

#GET UN SOLO DATO
@app.route('/carritos/<id>', methods=['GET'])
def getCarritoId(id):
    unCarrito =Carrito.query.get(id)
    if not unCarrito:
        return jsonify({'Error':'Carro no encotrado'})
    return carrito_schema.jsonify(unCarrito)

#POST UN DATO
@app.route('/carritos', methods=['POST'])
@token_required
def insertCarro(current_user):
    #data = request.get_json(force=True)
    UserId = current_user.idUser
    modelo = request.form['Modelo']#data['Modelo']
    desc = request.form['Desc']
    
    image = request.files['Imagen']
    nombreFILE = secure_filename(image.filename)
    basedir = os.path.abspath(os.path.dirname(__file__))

    image.save(os.path.join(basedir, app.config['UPLOAD_FOLDER'], nombreFILE))
    imagen = os.path.join(basedir, app.config['UPLOAD_FOLDER'], nombreFILE)
        
        
    nuevoCarro = Carrito(UserId, modelo, desc, imagen)
    db.session.add(nuevoCarro)
    db.session.commit()
    return jsonify({'Mensaje':'Carro agregado'})

#PUT
@app.route('/carritos/<id>', methods=['PUT'])
@token_required
def updateCarro(current_user, id):
    carroSelec = Carrito.query.get(id)

    if not carroSelec:
        return jsonify({'Error':'Carro no encotrado'})

    if current_user.idUser != carroSelec.UserId:
        return jsonify({'Error':'No autorizado'})

    UserId = current_user.idUser
    modelo = request.form['Modelo']#data['Modelo']
    desc = request.form['Desc']
    
    image = request.files['Imagen']
    nombreFILE = secure_filename(image.filename)
    basedir = os.path.abspath(os.path.dirname(__file__))

    image.save(os.path.join(basedir, app.config['UPLOAD_FOLDER'], nombreFILE))
    imagen = os.path.join(basedir, app.config['UPLOAD_FOLDER'], nombreFILE)
        
    carroSelec.UserId = UserId
    carroSelec.modelo = modelo
    carroSelec.desc = desc
    carroSelec.imagen = imagen
    
    db.session.commit()
    return jsonify({'Mensaje':'Carro actualizadeo'})

#DELETE
@app.route('/carritos/<id>', methods=['DELETE'])
@token_required
def deleteCarro(current_user, id):
    carroSelec = Carrito.query.get(id)

    if not carroSelec:
        return jsonify({'Error':'Carro no encotrado'})

    if current_user.idUser != carroSelec.UserId:
        return jsonify({'Error':'No autorizado'})
    
    db.session.delete(carroSelec)
    db.session.commit()
    return jsonify({'Mensaje':'Carro borrado'})

#Mensaje de bienvenida
@app.route('/',methods=['GET'])
def index():
    return jsonify({'Mensaje':'Bienvenido'})

if __name__=="__main__":
    app.run(debug=True)

