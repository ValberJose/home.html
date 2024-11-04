from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import os
import smtplib
import json
import random
import string
import re
import openpyxl
from dotenv import load_dotenv
from email.mime.text import MIMEText
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from flask import make_response
import streamlit as st

# Configurar logging para debug
logging.basicConfig(level=logging.DEBUG)

# Carregar variáveis de ambiente
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Caminho para o arquivo de configuração
config_path = r'C:\Users\User\OneDrive - Mangels Industrial SA\WORKTIMER site\Worktimer_site\worktimer_site\config_2.json'

# Carregar configurações
with open(config_path, 'r') as file:
    config = json.load(file)


def send_email(to_email, subject, body):
    """
    Envia um e-mail com o codigo de verificação para o endereço de e-mail especificado.

    Args:
        to_email (str): O endereço de e-mail para o qual será enviado o e-mail.
        subject (str): O assunto do e-mail.
        body (str): O corpo do e-mail.
    """
    from_email = os.getenv('EMAIL_USER')
    email_password = os.getenv('EMAIL_PASSWORD')
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))

    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.set_debuglevel(1)  # Nível de debug para SMTP

        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(from_email, email_password)
        server.sendmail(from_email, to_email, msg.as_string())
        logging.debug("E-mail enviado com sucesso!")
        server.quit()
    except smtplib.SMTPAuthenticationError as auth_err:
        logging.error(f"Erro de autenticação ao enviar e-mail: {auth_err.smtp_code} - {auth_err.smtp_error}")
        raise auth_err
    except Exception as e:
        logging.error(f"Erro ao enviar e-mail: {e}")
        raise e


def generate_verification_code(length=7):
    """
    Gera um código de verificação aleatório com o comprimento especificado.

    Args:
        length (int): O comprimento do código de verificação. Padrão é 7.

    Returns:
        str: O código de verificação gerado.
    """
    characters = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
    return ''.join(random.choices(characters, k=length))


def validate_password(password):
    """
    Valida se a senha atende aos critérios especificados (mínimo 7 caracteres, no minimo uma letra maiúscula, um caractere especial e um número).

    Args:
        password (str): A senha a ser validada.

    Returns:
        tuple: Quatro valores booleanos indicando a conformidade da senha com os critérios.
    """
    has_upper = re.search(r'[A-Z]', password) is not None
    has_number = re.search(r'[0-9]', password) is not None
    has_special = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None
    is_long_enough = len(password) >= 7
    return has_upper, has_number, has_special, is_long_enough


def validate_email_and_username(email, username):
    """
    Valida se o e-mail e o nome de usuário atendem ao criterio de validação dominio permitido (" @mangels.com.br").

    Args:
        email (str): O e-mail a ser validado.
        username (str): O nome de usuário a ser validado.

    Returns:
        tuple: Boolean indicando se são válidos e uma mensagem explicativa.
    """
    if not email.endswith('@mangels.com.br'):
        return False, "O e-mail deve ser do domínio @mangels.com.br."

    if os.path.exists(config['login_path']):
        workbook = openpyxl.load_workbook(config['login_path'])
        sheet = workbook.active
        for row in sheet.iter_rows(values_only=True):
            if row[3] == email:
                return False, "Este e-mail já está cadastrado."
            if row[1] == username:
                return False, "Este nome de usuário já está em uso."
    return True, "E-mail e nome de usuário disponíveis."


def save_user_to_excel(full_name, username, email, password, verified="Não"):
    """
    Salva o usuário no arquivo Excel com os detalhes fornecidos.

    Args:
        full_name (str): O nome completo do usuário.
        username (str): O nome de usuário.
        email (str): O endereço de e-mail.
        password (str): A senha do usuário.
        verified (str): Status de verificação. Padrão é "Não". (Até que o codigo de verificação seja fornecido, depois passará a "Sim")
    """
    try:
        workbook = openpyxl.load_workbook(config['login_path'])
        sheet = workbook.active
    except FileNotFoundError:
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.append(["Nome Completo", "Usuário", "Senha", "E-mail", "Verificado"])

    hashed_password = generate_password_hash(password)
    sheet.append([full_name, username, hashed_password, email, verified])
    workbook.save(config['login_path'])
    logging.debug(f"Usuário {username} salvo na planilha com sucesso!")


def is_logged_in():
    """
    Verifica se o usuário está logado.

    Returns:
        bool: True se o usuário estiver logado na sessão, False caso contrário.
    """
    return 'user' in session


@app.route('/')
def index():
    """
    Rota inicial que redireciona para a página de login.

    Returns:
        redirect: Redireciona para a página de login.
    """
    return redirect(url_for('login_page'))


@app.route('/login_page')
def login_page():
    """
    Rota que exibe a página de login.

    Returns:
        render_template: Renderiza o template da página de login.
    """
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    """
    Rota para realizar o login do usuário.

    Returns:
        redirect: Redireciona conforme o resultado do login.
    """
    username = request.form['username']
    password = request.form['password']

    if not username or not password:
        flash("Todos os campos são obrigatórios!", "danger")
        return redirect(url_for('login_page'))

    try:
        workbook = openpyxl.load_workbook(config['login_path'])
        sheet = workbook.active
    except FileNotFoundError:
        flash("Usuário ou senha incorretos.", "danger")
        return redirect(url_for('login_page'))

    user_found = False
    for row in sheet.iter_rows(min_row=2, values_only=True):
        stored_username = row[1]
        stored_password_hash = row[2]

        if stored_username == username:
            user_found = True
            if check_password_hash(stored_password_hash, password):
                session['user'] = username  # Salva o estado de login na sessão
                flash(f"Bem-vindo, {username}!", "success")
                logging.debug(f"Usuário {username} logado com sucesso.")
                return redirect(url_for('home_page'))
            else:
                flash("Usuário ou senha incorretos.", "danger")
                logging.debug(f"Senha incorreta para o usuário {username}.")
                return redirect(url_for('login_page'))

    if not user_found:
        flash("Usuário ou senha incorretos.", "danger")
        logging.debug("Nome de usuário não encontrado.")
        return redirect(url_for('login_page'))


@app.after_request
def add_security_headers(response):
    """
    Adiciona cabeçalhos de segurança às respostas do servidor.

    Args:
        response : A resposta do Flask.

    Returns:
        response: A resposta do Flask com cabeçalhos de segurança adicionados.
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.route('/home_page')
def home_page():
    """
    Rota para exibir a página inicial após o login.

    Returns:
        render_template | redirect: Redireciona para a página de login se não estiver logado, ou renderiza a página inicial.
    """
    if not is_logged_in():
        response = make_response(redirect(url_for('login_page')))
        response.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        response.headers.add('Pragma', 'no-cache')
        response.headers.add('Expires', '0')
        return response

    response = make_response(render_template('home.html', username=session['user']))
    response.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
    response.headers.add('Pragma', 'no-cache')
    response.headers.add('Expires', '0')
    return response


@app.route('/create_account')
def create_account_page():
    """
    Rota que exibe a página de criação de conta.

    Returns:
        render_template: Renderiza o template da página de criação de conta.
    """
    return render_template('create_account.html')


@app.route('/create_account', methods=['POST'])
def create_account():
    """
    Rota para criar uma nova conta de usuário.

    Returns:
        render_template | redirect: Renderiza a página de verificação ou redireciona conforme o resultado da criação.
    """
    full_name = request.form['full_name']
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    verification_code = generate_verification_code()

    if not full_name or not username or not email or not password:
        flash("Todos os campos são obrigatórios!", "danger")
        return redirect(url_for('create_account_page'))

    if not all(validate_password(password)):
        flash("A senha deve conter pelo menos uma letra maiúscula, um caractere especial e um número.", "danger")
        return redirect(url_for('create_account_page'))

    is_valid, message = validate_email_and_username(email, username)
    if not is_valid:
        flash(message, "danger")
        return redirect(url_for('create_account_page'))

    try:
        send_email(email, "Código de Verificação", f"Seu código de verificação é: {verification_code}")
        save_user_to_excel(full_name, username, email, password)

        logging.debug(f"Código de verificação enviado para {email}.")
        return render_template('verify.html', full_name=full_name, username=username, email=email, password=password,
                               code=verification_code)
    except Exception as e:
        logging.error(f"Erro ao enviar e-mail de verificação: {e}")
        flash(f"Erro ao enviar e-mail de verificação: {e}", "danger")
        return redirect(url_for('create_account_page'))


@app.route('/verify', methods=['POST'])
def verify():
    """
    Rota para verificar o código de verificação e completar a criação da conta.

    Returns:
        render_template | redirect: Renderiza a página de verificação ou redireciona conforme o resultado da verificação.
    """
    full_name = request.form['full_name']
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    code = request.form['code']
    submitted_code = request.form['submitted_code']

    if code == submitted_code:
        try:
            workbook = openpyxl.load_workbook(config['login_path'])
            sheet = workbook.active
            for row in sheet.iter_rows(min_row=2):
                if row[3].value == email:
                    row[4].value = "Sim"
            workbook.save(config['login_path'])
            flash("Conta criada com sucesso!", "success")
            logging.debug(f"Conta verificada para {email}.")
            return redirect(url_for('login_page'))
        except Exception as e:
            logging.error(f"Erro ao salvar verificação: {e}")
            flash("Erro ao salvar verificação, tente novamente.", "danger")
            return render_template('verify.html', full_name=full_name, username=username, email=email,
                                   password=password, code=code)
    else:
        flash("Código de verificação incorreto!", "danger")
        return render_template('verify.html', full_name=full_name, username=username, email=email, password=password,
                               code=code)


@app.route('/recover_password')
def recover_password_page():
    """
    Rota que exibe a página de recuperação de senha.

    Returns:
        render_template: Renderiza o template da página de recuperação de senha.
    """
    return render_template('recover_password.html')


@app.route('/recover_password', methods=['POST'])
def recover_password():
    """
    Rota para iniciar o processo de recuperação de senha.

    Returns:
        redirect: Redireciona conforme o resultado da recuperação.
    """
    email = request.form['email']

    if not email:
        flash("O campo de e-mail não pode estar vazio.", "danger")
        return redirect(url_for('recover_password_page'))

    if os.path.exists(config['login_path']):
        workbook = openpyxl.load_workbook(config['login_path'])
        sheet = workbook.active
        for row in sheet.iter_rows(values_only=True):
            if row[3] == email:
                verification_code = generate_verification_code()
                try:
                    send_email(email, "Código de Recuperação de Senha",
                               f"Seu código de recuperação é: {verification_code}")
                    return redirect(url_for('verify_password_page', email=email, code=verification_code))
                except Exception as e:
                    flash(f"Erro ao enviar e-mail de recuperação: {e}", "danger")
                    return redirect(url_for('recover_password_page'))

    flash("O e-mail fornecido não foi encontrado.", "danger")
    return redirect(url_for('recover_password_page'))


@app.route('/verify_password', methods=['GET', 'POST'])
def verify_password_page():
    """
    Rota para verificar o código de recuperação de senha.

    Returns:
        render_template: Renderiza o template da página de verificação de senha.
    """
    if request.method == 'POST':
        email = request.form['email']
        code = request.form['code']
        submitted_code = request.form['submitted_code']

        if code == submitted_code:
            flash("Código de verificação correto! Redefina sua senha.", "success")
            return render_template('reset_password.html', email=email)
        else:
            flash("Código de verificação incorreto!", "danger")
            return render_template('verify_password.html', email=email, code=code)

    email = request.args.get('email')
    code = request.args.get('code')
    return render_template('verify_password.html', email=email, code=code)


@app.route('/reset_password', methods=['POST'])
def reset_password():
    """
    Rota para redefinir a senha do usuário.

    Returns:
        redirect: Redireciona conforme o resultado da redefinição de senha.
    """
    email = request.form['email']
    new_password = request.form['new_password']

    if not all(validate_password(new_password)):
        flash(
            "A nova senha deve conter pelo menos uma letra maiúscula, um caractere especial e um número, e ter pelo menos 7 caracteres.",
            "danger")
        return render_template('reset_password.html', email=email)

    try:
        workbook = openpyxl.load_workbook(config['login_path'])
        sheet = workbook.active
        for row in sheet.iter_rows():
            if row[3].value == email:
                row[2].value = generate_password_hash(new_password)
        workbook.save(config['login_path'])
        flash("Senha redefinida com sucesso! Faça login com sua nova senha.", "success")
        return redirect(url_for('login_page'))
    except Exception as e:
        logging.error(f"Erro ao salvar nova senha: {e}")
        flash("Erro ao salvar nova senha, tente novamente.", "danger")
        return render_template('reset_password.html', email=email)


@app.route('/saveActivity', methods=['POST'])
def save_activity():
    """
    Rota para salvar atividade em um arquivo Excel.

    Returns:
        jsonify: Mensagem de sucesso ou erro.
    """
    data = request.json
    logging.info(f"Recebido: {data}")  # Verifique se os dados estão corretos

    file_name = 'Tempo_Atividades.xlsx'

    try:
        if os.path.exists(file_name):
            workbook = openpyxl.load_workbook(file_name)
            sheet = workbook.active
        else:
            workbook = openpyxl.Workbook()
            sheet = workbook.active
            sheet.append([
                "Categoria", "Âmbito", "Empresa Nome", "Código", "Tributo", "Atividade Selecionada",
                "Dia início", "Hora início", "Dia término", "Hora término", "Tempo de conclusão", "Responsável"
            ])

        sheet.append([
            data['categoria'], data['ambito'], data['empresaNome'], data['codigo'], data['tributo'],
            data['atividadeSelecionada'], data['diaInicio'], data['horaInicio'],
            data['diaTermino'], data['horaTermino'], data['tempoConclusao'], data['responsavel']
        ])
        workbook.save(file_name)
        logging.info(f"Registro salvo com sucesso: {data}")

        return jsonify(message="Atividade salva com sucesso!"), 200

    except Exception as e:
        logging.error(f"Erro ao salvar atividade: {e}")
        return jsonify(message="Erro ao salvar a atividade."), 500



@app.route('/saveJustificativa', methods=['POST'])
def save_justificativa():
    """
    Rota para salvar justificativa em um arquivo Excel.

    Returns:
        jsonify: Mensagem de sucesso ou erro.
    """
    data = request.json
    file_name = 'Justificativa.xlsx'

    if os.path.exists(file_name):
        workbook = openpyxl.load_workbook(file_name)
        sheet = workbook.active
    else:
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.append([
            "Categoria", "Âmbito", "Empresa Nome", "Código", "Tributo",
            "Dia início", "Hora início", "horaInicioDaPausa","tempoDeInicio", "Responsável","Justificativa"
        ])

    sheet.append([
        data['atividade'],
        data['Âmbito'],
        data['Empresa Nome'],
        data['Código'],
        data['Tributo'],
        data['diaInicio'],
        data['horaInicio'],
        data['horaInicioDaPausa'],
        data['tempoDeInicio'],
        data['responsavel'],
        data['justificativa']
    ])

    workbook.save(file_name)
    return jsonify(message="Justificativa salva com sucesso!"), 200


@app.route('/logout', methods=['POST'])
def logout():
    """
    Rota para fazer logout do usuário.

    Returns:
        redirect: Redireciona para a página de login.n
    """
    session.clear()
    response = make_response(redirect(url_for('login_page')))
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/check_session')

def check_session():
    if 'user' in session:
        return '', 200
    return '', 401


if __name__ == '__main__':
    app.run(debug=True)
