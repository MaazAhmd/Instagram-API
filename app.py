from flask import Flask, render_template, request, redirect, flash, url_for
import instaloader
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, current_user, login_required, logout_user
from flask_session import Session
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'  
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
Session(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    account_owner_username = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
@login_required
def instagram_loader():
    profile_data = {}
    flagged_accounts = []

    if request.method == 'POST':
        username = request.form.get('username')
        password = current_user.password
        account_owner_username = current_user.account_owner_username
        email = current_user.email
        flagged_accounts = request.form.getlist('flagged_accounts')
        if flagged_accounts:
            profile_data['flagged_accounts'] = flagged_accounts
        else:
            L = instaloader.Instaloader()
            session_file_path = f'{account_owner_username}.session'
                    
            try:
                if os.path.exists(session_file_path):
                    L.load_session_from_file(account_owner_username, session_file_path)
                    print("Session loaded successfully.")
                else:
                    L.login(email, password)
                    L.save_session_to_file(session_file_path)
                    print(f"Session saved at {session_file_path}.")
                profile = instaloader.Profile.from_username(L.context, username)
                followers = [follower.username for follower in profile.get_followers()]
                following = [followee.username for followee in profile.get_followees()]
                not_following_back = [user for user in following if user not in followers]

                profile_data = {
                    'username': profile.username,
                    'fullname': profile.full_name,
                    'num_posts': profile.mediacount,
                    'followers_count': profile.followers,
                    'following_count': profile.followees,
                    'bio': profile.biography,
                    'followers_names': followers,
                    'following_names': following,
                    'not_following_back': not_following_back
                }

            except instaloader.exceptions.TwoFactorAuthRequiredException:
                profile_data['error'] = "2FA is required. Please enable it in your settings."
            except instaloader.exceptions.BadCredentialsException:
                profile_data['error'] = "Invalid login credentials."
            except instaloader.exceptions.ProfileNotExistsException:
                profile_data['error'] = "The username does not exist."
            except instaloader.exceptions.ConnectionException:
                profile_data['error'] = "Failed to connect to Instagram. Please try again later."
            except Exception as e:
                profile_data['error'] = f"An unexpected error occurred: {e}"

    return render_template('instagram_loader.html', profile_data=profile_data)


@app.route('/show_selected', methods=['POST'])
def show_selected():
    flagged_accounts = request.form.getlist('flagged_accounts')
    return render_template('show_selected.html', flagged_accounts=flagged_accounts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        account_owner_username = request.form['owner_username']

        L = instaloader.Instaloader()
        try:
            L.login(email, password) 
            session_file_path = f'{account_owner_username}.session'
            L.save_session_to_file(session_file_path)

            user = User.query.filter_by(email=email).first()

            if not user:
                user = User(email=email, password=password, account_owner_username=account_owner_username)
                db.session.add(user)
                db.session.commit()

            login_user(user)  
            flash('Logged in successfully!', 'success')
            return redirect('/')
        except instaloader.exceptions.BadCredentialsException:
            flash('Invalid Instagram credentials.', 'danger')
        except instaloader.exceptions.TwoFactorAuthRequiredException:
            flash('2FA is required. Please enable it in your settings.', 'danger')
        except Exception as e:
            flash(f"Login failed: {e}", 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
