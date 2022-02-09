from datetime import datetime
from flask import Flask
from flask import render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'kola777_den'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tilt.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


# Дата доставки: 10.01.2022;
# Точка доставки: ул. Пушкина;


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)


def __repr__(self):
    return '<Article %>' % self.id


class User (db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
@app.route('/home')
@login_required
def glavka():
    return render_template("glavka.html")


@app.route('/Onas')
@login_required
def Onas():
    return render_template("Onas.html")


@app.route('/zakazi')
@login_required
def zakazi():
    articles = Article.query.order_by(Article.date.desc()).all()
    return render_template("zakazi.html", articles=articles)


@app.route('/zakazi/<int:id>')
@login_required
def zakaz_detail(id):
    article = Article.query.get(id)
    return render_template("zakaz_detail.html", article=article)


@app.route('/zakazi/<int:id>/del')
@login_required
def zakaz_delete(id):
    article = Article.query.get_or_404(id)

    try:
        db.session.delete(article)
        db.session.commit()
        return redirect('/zakazi')
    except:
        return "Произошла ошибка при при удалении заказа"


@app.route('//zakazi/<int:id>/update', methods=['POST', 'GET'])
@login_required
def zakaz_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.title = request.form['title']
        article.intro = request.form['intro']
        article.text = request.form['text']

        try:
            db.session.commit()
            return redirect('/zakazi')
        except:
            return "Произошла ошибка при редактировании заказа"
    else:
        return render_template("zakaz_update.html", article=article)


@app.route('/create_zakaz', methods=['POST', 'GET'])
@login_required
def create_zakaz():
    if request.method == "POST":
        title = request.form['title']
        intro = request.form['intro']
        text = request.form['text']

        article = Article(title=title, intro=intro, text=text)

        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/zakazi')
        except:
            return "Произошла ошибка при создании заказа"
    else:
        return render_template("create_zakaz.html")


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            next_page = request.args.get('next')

            return render_template("glavka.html")
        else:
            flash('Login or password is not correct')
    else:
        flash('Please fill login and password fields')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Please, fill all fields!')
        elif password != password2:
            flash('Passwords are not equal!')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello_world'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response


if __name__ == "__main__":
    app.run(debug=True)
