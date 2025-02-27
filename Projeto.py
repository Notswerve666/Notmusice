from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import timedelta  

app = Flask(__name__)
app.secret_key = 'your_secret_key'  
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
    return users_db.get(user_id)

@app.route('/')
def index():
    if current_user.is_authenticated:  
        return render_template('index.html', username=current_user.username)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember')

        
        user = next((u for u in users_db.values() if u.username == username), None)
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember_me)  
            return redirect(url_for('index'))
        else:
            flash('Usuário ou senha incorretos!', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']

        if password != confirm_password:
            flash('As senhas não coincidem!', 'error')
            return redirect(url_for('register'))

        if any(u.username == username for u in users_db.values()):
            flash('Usuário já existe!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user_id = len(users_db) + 1  
        new_user = User(id=user_id, username=username, email=email, password=hashed_password)
        users_db[user_id] = new_user  
        flash('Usuário registrado com sucesso!', 'success')

        login_user(new_user)  
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()  
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
