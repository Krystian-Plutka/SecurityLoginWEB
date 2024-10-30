from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash
from . import db
from .models import User, Note, Role, Permission, user_roles, role_permissions
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_login import login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from datetime import datetime
import uuid
import pyotp
import qrcode
import qrcode.image.pil
import os

mail = Mail()
auth = Blueprint('auth', __name__)

@auth.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        otp_code = request.form.get('otp_code')
        
        user = User.query.filter_by(email=email).first() 
        if user:
            print(f"Stored OTP Secret Code: {user.otp_secret}")
            if check_password_hash(user.password, password):
                 log_event(user.id, 'Poprawne logowanie')
                 if user.otp_secret:
                     otp = pyotp.TOTP(user.otp_secret)
                     print(f"OTP Code: {otp_code}") #debugowanie
                     print(f"OTP Valid: {otp.verify(otp_code)}")
                     if not otp.verify(otp_code):
                         log_event(user.id, 'Nieprawidłowy kod weryfikacyjny')
                         flash('Niepoprawny kod weryfikacyjny', category='error')
                         return redirect(url_for('auth.login'))
                 flash('Jesteś Zalogowany!', category='success')
                 login_user(user, remember=True)
                 return redirect(url_for('views.home'))
            else:
                log_event(user.id, "Nieprawidłowy login: złe hasło")
                flash('Niepoprawne Hasło, Spróbuj ponownie', category="error")    
        else:
            log_event(None, f"Nieprawidłowy E-mail: {email}")
            flash('Email jest nie poprawny, Spróbuj ponownie', category='error')

    return render_template("login.html", user=current_user)

def log_event(user_id, message):
    with open('security_log.txt', 'a') as f:
        log_message = f"User ID: {user_id}, Event: {message}, Time: {datetime.now()}\n"
        f.write(log_message)

    if "Nieudana próba logowania" in message:
        send_alert_email(user_id, message)

def send_alert_email(user_id, message):
    user = User.query.get(user_id) if user_id else None
    recipient_email = user.email if user else "admin@example.com"
    msg = Message("Alert Bezpieczeństwa", sender="nore")

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email o takiej nazwie już istnieje!', category='error')
        if len(email) < 5:
            flash('Nazwa emaila musi być większa niż 4 liter', category='error')
        elif len(first_name) < 2:
            flash('Nazwa użytkownika musi być większa niż 1 litrera', category='error')
        elif password != confirm_password:
            flash('Hasła nie są takie same', category='error')
        elif len(password) < 7:
            flash('Hasło musi mieć co najmniej 7 liter', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(confirm_password, method="pbkdf2:sha256"))
            
            db.session.add(new_user)
            db.session.commit()
            
            login_user(new_user, remember=True)
            flash('Konto zostało utworzone', category='success')
            return redirect(url_for('views.home'))
    
    return render_template("sign_up.html", user=current_user)

@auth.route('/login2')
def login2():
    return render_template("login2.html")

@auth.route('/forum', methods=['GET', 'POST'])
@login_required
def forum():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash('Post jest za krótki!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Post został dodany!', category='success')  

    return render_template("forum.html", user=current_user)

@auth.route('/generate-otp', methods=['GET', 'POST'])
@login_required
def generate_otp():
    if request.method == "POST":
        user = current_user
        if user.otp_secret:
            flash('Kod weryfikacyjny jest już ustawiony', category="error")
        else:
            otp = pyotp.TOTP(pyotp.random_base32())
            user.otp_secret = otp.secret
            db.session.commit()

            # Generowanie QR kodu
            qr = qrcode.QRCode()
            qr.add_data(otp.provisioning_uri(name=user.email, issuer_name="Security LoginWEB"))    
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')

            static_folder = os.path.join(os.path.dirname(__file__), 'static')
            images_folder = os.path.join(static_folder, 'images')

            qr_code_path = os.path.join(images_folder, 'otp_qr.png')

            #Zapisanie obrazka Kodu QR
            img.save(qr_code_path)

            #Debugowanie:
            print(f"Wygenerowany kod OTP Secret: {user.otp_secret}")

            flash('Kod weryfikacyjny został wygenerowany.', category='success')
            flash('Zeskanuj kod QR i zachowaj ten kod w aplikacji')

            # Zwrot widoku po poprawnym wygenerowaniu
            return render_template('generate-otp.html', qr_code_path='images/otp_qr.png')

    # W przypadku GET lub innych sytuacji zawsze renderuj szablon
    return render_template('generate-otp.html')    

@auth.route('/reset-data', methods=['GET', 'POST'])
@login_required
def reset_data():
    if request.method == 'POST':
        new_email = request.form.get('email')
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        user = current_user
# reset emaila
        if new_email and new_email != user.email:
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user:
                flash('Email o takiej nazwie już istnieje!', category="error")
            elif len(new_email) < 5:
                flash('Nazwa emaila musi być większa niż 4 litery', category='error')
            else:
                user.email = new_email
                flash('Email został zmieniony', category="success")
#reset nazwy usera
        if new_username and new_username != user.first_name:
            if len(new_username) < 2:
                flash('Nazwa użytkownika musi być większa niż 1 litera', category='error')
            else:
                user.first_name = new_username
                flash("Nazwa użytkownika została zmieniona", category="success")
#Reset Hasła:
        if new_password:
            if new_password != confirm_password:
                flash('Hasła nie są takie same!', category="error")
            elif len(new_password) < 7:
                flash("Hasło musi mieć co najmniej 7 liter",category="error")
            else:
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                flash('Hasło zostało zmienione', category="success")                                            

        db.session.commit()
        return redirect(url_for('auth.reset_data'))
    return render_template('reset_data.html', user=current_user)

@auth.route('/manage-roles', methods=['GET', 'POST'])
@login_required
def manage_roles():
    
    role_name = None
    permission_name = None
    user_id = None

    roles = Role.query.all()
    permissions = Permission.query.all()
    users = User.query.all()

    if request.method == 'POST':
        role_name = request.form.get('role_name')
        permission_name = request.form.get('permission_name')
        user_id = request.form.get('user_id')

    if role_name:
        
        existing_role = Role.query.filter_by(name=role_name).first()
        if existing_role:
            flash(f"Rola '{role_name}' już istnieje", category="error")
        else:    
          new_role = Role(name=role_name)
          db.session.add(new_role)
          db.session.commit()
          flash('Rola została dodana', category="success")

    if permission_name:
        existing_permission = Permission.query.filter_by(name=permission_name).first()
        if existing_permission:
            flash(f"Uprawnienie '{permission_name}' już istnieje", category="error")
        else:
            role = Role.query.filter_by(name=role_name).first()
        if role:
            new_permission = Permission(name=permission_name)
            role.permissions.append(new_permission)
            db.session.commit()
            flash('Uprawnienie zostało dodane do roli', category='success') 

        if user_id and role_name:
            user = User.query.get(user_id)
            role = Role.query.filter_by(name=role_name).first()
            if user and role:
                user.roles.append(role)
                db.session.commit()
                flash('Rola została dodana i przypisana do użytkownika!', category='success')

    return render_template('manage_roles.html', roles=roles, permissions=permissions, users=users)
        
@auth.route('/view-logs')
@login_required
def view_login():
    with open('security_log.txt', 'r') as f:
        logs = f.readlines()
    return render_template('view_logs.html', logs=logs)    