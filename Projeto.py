from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import timedelta  
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Gera uma chave secreta aleatória
app.permanent_session_lifetime = timedelta(days=7)  

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  

users_db = {}

class User(UserMixin):
    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    print(f'Carregando usuário com id: {user_id}')
    return users_db.get(int(user_id))  # Convertendo para int para buscar no dicionário

@app.route('/')
def index():
    if current_user.is_authenticated:  
        print(f'Usuário logado: {current_user.username}')
        return render_template('index.html', username=current_user.username)
    print('Usuário não logado.')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember')

        # Busca o usuário pelo nome
        user = next((u for u in users_db.values() if u.username == username), None)
        print(f'Buscando usuário: {username}')
        print(f'Usuário encontrado? {user}')
        
        if user and check_password_hash(user.password, password):
            print(f'Login bem-sucedido para {username}')
            login_user(user, remember=remember_me)  # Faz o login do usuário
            print(f'Usuário autenticado: {current_user.is_authenticated}')
            return redirect(url_for('index'))
        else:
            flash('Usuário ou senha incorretos!', 'error')
            print('Erro de login: Usuário ou senha incorretos')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        print(f'Registrando usuário: {username}')

        if password != confirm_password:
            flash('As senhas não coincidem!', 'error')
            print('Erro: As senhas não coincidem')
            return redirect(url_for('register'))

        if any(u.username == username for u in users_db.values()):
            flash('Usuário já existe!', 'error')
            print(f'Erro: O usuário {username} já existe')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user_id = len(users_db) + 1  # Define um ID único
        new_user = User(id=user_id, username=username, email=email, password=hashed_password)
        users_db[user_id] = new_user  # Armazena o usuário no "banco de dados"
        flash('Usuário registrado com sucesso!', 'success')

        login_user(new_user)  # Faz o login após o registro
        print(f'Usuário {username} registrado com sucesso')
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Faz logout do usuário
    print('Usuário deslogado.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
