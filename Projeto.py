from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Use a secret key to enable session management

# Exemplo de banco de dados em memória (você deve usar um banco real)
users_db = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Verificar se o usuário existe
        if username in users_db:
            # Verificar se a senha está correta
            stored_password = users_db[username]['password']
            if check_password_hash(stored_password, password):
                session['username'] = username  # Iniciar sessão do usuário
                return redirect(url_for('index'))
            else:
                flash('Senha incorreta!', 'error')
        else:
            flash('Usuário não encontrado!', 'error')
        
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

        # Verificar se o usuário já existe
        if username in users_db:
            flash('Usuário já existe!', 'error')
            return redirect(url_for('register'))

        # Salvar o novo usuário (com senha criptografada)
        hashed_password = generate_password_hash(password)
        users_db[username] = {'password': hashed_password, 'email': email}
        flash('Usuário registrado com sucesso!', 'success')
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remover o usuário da sessão
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
