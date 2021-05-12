import datetime
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from hashlib import md5

import jwt
from flask import Flask, render_template, redirect, request, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandex'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=365)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
                                        'sqlite:///' + os.path.join(basedir, 'db/blogs.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
moment = Moment(app)
login_manager = LoginManager(app)

followers = db.Table('followers',
                     db.Column('follower_id', db.Integer, db.ForeignKey('users.id')),
                     db.Column('followed_id', db.Integer, db.ForeignKey('users.id')))


class User(UserMixin, SerializerMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=True)
    about = db.Column(db.String, nullable=True)
    email = db.Column(db.String, index=True, unique=True, nullable=True)
    hashed_password = db.Column(db.String, nullable=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    messages_sent = db.relationship('Message',
                                    foreign_keys='Message.sender_id',
                                    backref='author', lazy='dynamic')
    messages_received = db.relationship('Message',
                                        foreign_keys='Message.recipient_id',
                                        backref='recipient', lazy='dynamic')

    def __repr__(self):
        return f'<User> {self.id} {self.name} {self.email}'

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        followed = Posts.query.join(
            followers, (followers.c.followed_id == Posts.user_id)).filter(
            followers.c.follower_id == self.id)
        own = Posts.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Posts.created_date.desc())

    def get_reset_password_token(self):
        return jwt.encode(
            {'reset_password': self.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600)},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String, nullable=True)
    content = db.Column(db.Text, nullable=True)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    body = db.Column(db.String(140))
    created_date = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow())
    last_message_read_time = db.Column(db.DateTime)

    def __repr__(self):
        return '<Message {}>'.format(self.body)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.datetime.utcnow()
        db.session.commit()


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.errorhandler(404)
def error_404(error):
    return render_template('error_404.html')


@app.route("/")
def index():
    email = request.args.get('email')
    password = request.args.get('password')
    message1 = request.args.get('message1')
    message2 = request.args.get('message2')
    if email and password:
        user = User.query.filter(User.email == email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect('/')
        return render_template("index.html", message1='Error', message2='Неправильный логин или пароль')
    if message1 and message2:
        return render_template("index.html", message1=message1, message2=message2)
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        password_again = request.form['password_again']
        if password_again != password:
            return render_template('register_form.html', message1='Error', message2='Пароли не совпадают')
        if User.query.filter(User.email == email).first():
            return render_template('register_form.html', message1='Error',
                                   message2='Пользователь с таким email уже существует')
        user = User(
            name=name,
            email=email
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    return render_template('register_form.html')


@app.route('/users')
@login_required
def users():
    q = request.args.get('q')
    page = request.args.get('page')
    if page and page.isdigit():
        page = int(page)
    else:
        page = 1
    if q:
        users = User.query.filter((User.name.contains(q)))
    else:
        users = User.query.order_by(User.created_date.desc())
    pages = users.paginate(page, per_page=5)
    return render_template('users.html', k='1', pages=pages, User=User, q=q)


@app.route('/user/<username>')
def profile(username):
    user = User.query.filter_by(name=username).first()
    return render_template('profile.html', user=user)


@app.route('/edit_profile/<username>', methods=['GET', 'POST'])
@login_required
def edit_profile(username):
    user = User.query.filter_by(name=username).first()
    if request.method == 'POST':
        name = request.form['name']
        about = request.form['about']
        user.name = name
        user.about = about
        db.session.commit()
        return redirect(url_for('profile', username=user.name))
    return render_template('edit_profile.html', user=user)


@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(name=username).first()
    current_user.follow(user)
    db.session.commit()
    return redirect(url_for('profile', username=user.name))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(name=username).first()
    if user is None:
        return redirect(url_for('index'))
    if user == current_user:
        return redirect(url_for('profile', username=user.name))
    current_user.unfollow(user)
    db.session.commit()
    return redirect(url_for('profile', username=user.name))


@app.route('/blog')
@login_required
def blog():
    q = request.args.get('q')
    page = request.args.get('page')
    if page and page.isdigit():
        page = int(page)
    else:
        page = 1
    if q:
        posts = Posts.query.filter((Posts.title.contains(q)) | (Posts.content.contains(q))).order_by(Posts.created_date.desc())
    else:
        posts = Posts.query.order_by(Posts.created_date.desc())
    pages = posts.paginate(page, per_page=5)
    return render_template('blog.html', k='1', pages=pages, User=User, q=q)


@app.route('/blog/followed')
@login_required
def blog_followed():
    q = request.args.get('q')
    page = request.args.get('page')
    if page and page.isdigit():
        page = int(page)
    else:
        page = 1
    if q:
        posts = current_user.followed_posts().filter((Posts.title.contains(q)) | (Posts.content.contains(q)))
    else:
        posts = current_user.followed_posts()
    pages = posts.paginate(page, per_page=5)
    return render_template('blog.html', k='1', pages=pages, User=User, q=q, followed='1')


@app.route('/blog/my_posts')
@login_required
def my_posts():
    q = request.args.get('q')
    page = request.args.get('page')
    if page and page.isdigit():
        page = int(page)
    else:
        page = 1
    if q:
        posts = Posts.query.filter(Posts.user_id == current_user.id).filter(
            (Posts.title.contains(q)) | (Posts.content.contains(q))).order_by(Posts.created_date.desc())
    else:
        posts = Posts.query.filter(Posts.user_id == current_user.id).order_by(Posts.created_date.desc())
    pages = posts.paginate(page, per_page=5)
    return render_template('blog.html', k='1', pages=pages, User=User, q=q, my='1')


@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def app_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = Posts(
            title=title,
            content=content,
            user_id=current_user.id,
            created_date=datetime.datetime.utcnow()
        )
        db.session.add(post)
        db.session.commit()
        return redirect('/blog')
    return render_template('add_post.html')


@app.route('/chat')
@login_required
def chat():
    chats = {}
    users = User.query.all()
    for user in users:
        if user == current_user:
            continue
        messages1 = Message.query.filter_by(author=current_user, recipient=user)
        messages2 = Message.query.filter_by(author=user, recipient=current_user)
        messages = messages1.union(messages2).order_by(Message.created_date.asc()).all()
        if len(messages) > 0:
            chats[user] = messages1.union(messages2).order_by(Message.created_date.asc()).all()
    return render_template('chat2.html', chats=chats, User=User)


@app.route('/chat/<username>', methods=['GET', 'POST'])
@login_required
def chat1(username):
    if request.method == 'POST':
        message = request.form['message']
        msg = Message(
            author=current_user,
            recipient=User.query.filter_by(name=username).first(),
            body=message,
            created_date=datetime.datetime.utcnow()
        )
        db.session.add(msg)
        db.session.commit()
    chats = {}
    users = User.query.all()
    for user in users:
        if user == current_user:
            continue
        messages1 = Message.query.filter_by(author=current_user, recipient=user)
        messages2 = Message.query.filter_by(author=user, recipient=current_user)
        messages = messages1.union(messages2).order_by(Message.created_date.asc()).all()
        if len(messages) > 0:
            chats[user] = messages1.union(messages2).order_by(Message.created_date.asc()).all()
    try:
        return render_template('chat1.html', messages=chats[User.query.filter_by(name=username).first()],
                           User=User, username=username, chats=chats)
    except KeyError:
        message = Message(
            author=current_user,
            recipient=User.query.filter_by(name=username).first(),
            body='text'
        )
        db.session.add(message)
        db.session.commit()
        for user in users:
            if user == current_user:
                continue
            messages1 = Message.query.filter_by(author=current_user, recipient=user)
            messages2 = Message.query.filter_by(author=user, recipient=current_user)
            messages = messages1.union(messages2).order_by(Message.created_date.asc()).all()
            if len(messages) > 0:
                chats[user] = messages1.union(messages2).order_by(Message.created_date.asc()).all()
        return render_template('chat1.html', messages=chats[User.query.filter_by(name=username).first()],
                               User=User, username=username, chats=chats)


@app.route('/reset_password_email', methods=['GET', 'POST'])
def reset_password_email():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            return render_template('reset_password_email.html', message1='Error',
                                   message2='Пользователя с таким email не существует')
        if user and user.email[user.email.find('@') + 1:] != 'mail.ru':
            return redirect(url_for('index', message1='Error', message2='Reset password only for mail.ru users'))
        else:
            send_password_reset_email(user)
            return redirect(url_for('index', message1='Info',
                                    message2='На вашу почту поступила инструкция по изменению пароля'))
    return render_template('reset_password_email.html')


@app.route('/reset_password_profile/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    if request.method == 'POST':
        password = request.form['password']
        password_again = request.form['password_again']
        if password != password_again:
            return render_template('reset_password_profile.html', message1='Error', message2='Пароли не совпадают')
        user.set_password(password)
        db.session.commit()
        return redirect('/')
    return render_template('reset_password_profile.html', user=user)


def send_password_reset_email(user):
    token = user.get_reset_password_token()
    msg = MIMEMultipart()
    addr = 'website_yandexlyceum_project@mail.ru'
    password = '326598asd'
    msg['From'] = addr
    msg['To'] = user.email
    msg['Subject'] = 'Reset Password'
    url = url_for('reset_password', token=token, _external=True)
    user = user.name
    html = f"""<p>Dear {user}</p>
<p>
    To reset your password
    <a href="{url}">
        click here
    </a>
</p>
<p>If you have not requested a password reset simply ignore this message</p>
<p>Sincerely</p>
<p>WebSite TeaM</p>"""
    msg.attach(MIMEText(html, 'html'))
    server = smtplib.SMTP('smtp.mail.ru', 25)
    server.starttls()
    server.login(addr, password)
    server.send_message(msg)
    server.quit()


if __name__ == '__main__':
    app.run(host='127.0.0.1', port='1014')
