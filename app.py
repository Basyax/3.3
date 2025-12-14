from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import datetime
import random
import psycopg2
# НОВЫЙ ИМПОРТ ДЛЯ АУТЕНТИФИКАЦИИ
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from forms import PostForm, CommentForm, RegistrationForm, LoginForm  # ДОБАВЛЕНЫ НОВЫЕ ФОРМЫ

# ========== Налаштування ==========\r\n
app = Flask(__name__)

app.config.from_mapping(
    SECRET_KEY='your-secret-key-change-this',

    # Параметри підключення до PostgreSQL
    DB_HOST='localhost',
    DB_NAME='mydatabase',
    DB_USER='postgres',
    DB_PASSWORD='1234'
)

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"postgresql+psycopg2://{app.config['DB_USER']}:"
    f"{app.config['DB_PASSWORD']}@{app.config['DB_HOST']}/"
    f"{app.config['DB_NAME']}"
)

app.config['SECRET_KEY'] = 'ваша_очень_секретная_строка'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Инициализация Bcrypt



login_manager = LoginManager(app)  # Инициализация Flask-Login
login_manager.login_view = 'login'  # Указываем, куда перенаправлять неавторизованных
login_manager.login_message_category = 'info'  # Категория flash-сообщений для входа
login_manager.login_message = 'Для доступа к этой странице необходимо войти.'

conn = psycopg2.connect(
    host=app.config['DB_HOST'],
    database=app.config['DB_NAME'],
    user=app.config['DB_USER'],
    password=app.config['DB_PASSWORD']
)


# Установка функции, которая загружает пользователя по ID для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ========== Моделі ==========\r\n

# Модель User теперь наследует UserMixin для работы с Flask-Login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)  # Хэш пароля
    name = db.Column(db.String(50), nullable=False, default="Гость")
    surname = db.Column(db.String(50), nullable=False, default="Автор")
    group = db.Column(db.String(10), nullable=False, default="N/A")

    # Связь с постами и комментариями
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='comment_author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

with app.app_context():
    db.create_all()

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    content = db.Column(db.String(400), nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    comments = db.relationship('Comment', backref='post', lazy=True, order_by="Comment.date_posted",
                               cascade="all, delete-orphan")
    transactions = db.relationship('Transaction', backref='post', lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    action = db.Column(db.String(50))
    description = db.Column(db.String(300))


# ========== Функції для работы с постами (Используют current_user) ==========\r\n

def log_transaction(post_id, action, description):
    tx = Transaction(post_id=post_id, action=action, description=description)
    db.session.add(tx)
    db.session.commit()


def add_post(title, content):
    # Проверка, что пользователь аутентифицирован
    if not current_user.is_authenticated:
        return None

    user = current_user
    new_post = Post(title=title, content=content, user_id=user.id)
    db.session.add(new_post)
    db.session.commit()
    log_transaction(new_post.id, 'POST_CREATE', f'Post "{title}" created by User #{user.id}.')
    return new_post.id


def update_post(post_id, new_title, new_content):
    post = Post.query.get(post_id)
    # Проверка: пост существует, пользователь залогинен, и он является автором
    if post and current_user.is_authenticated and post.author.id == current_user.id:
        old_title = post.title
        post.title = new_title
        post.content = new_content
        db.session.commit()
        log_transaction(post_id, 'POST_UPDATE', f'Post updated by User #{current_user.id}. Old title: "{old_title}".')
        return True
    return False


def delete_post(post_id):
    post = Post.query.get(post_id)
    # Проверка: пост существует, пользователь залогинен, и он является автором
    if post and current_user.is_authenticated and post.author.id == current_user.id:
        db.session.delete(post)
        db.session.commit()
        log_transaction(post_id, 'POST_DELETE', f'Post "{post.title}" deleted by User #{current_user.id}.')
        return True
    return False


# Створення таблиць при запуску
with app.app_context():
    db.create_all()


# ========== НОВЫЕ МАРШРУТЫ АУТЕНТИФИКАЦИИ ==========\r\n

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()

    if form.validate_on_submit():
        # Хешируем пароль
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password,
                    name=form.name.data, surname=form.surname.data, group=form.group.data)
        db.session.add(user)
        db.session.commit()
        flash(f'Аккаунт создан для {form.username.data}! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Регистрация', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Вход выполнен успешно!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Вход не выполнен. Проверьте email и пароль.', 'danger')

    return render_template('login.html', title='Вход', form=form)


@app.route("/logout")
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))


# ========== ОБНОВЛЕННЫЕ МАРШРУТЫ ==========\r\n

@app.route('/')
def index():
    if current_user.is_authenticated:
        options = [current_user.name, current_user.surname, current_user.group]
    else:
        options = ["Гость", "Читатель", "Неизвестный"]

    message = random.choice(options)
    return render_template('index.html', message=message)


@app.route('/posts')
def show_posts():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('posts.html', posts=posts)


# Только для залогиненных пользователей
@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()

    if form.validate_on_submit():
        new_id = add_post(form.title.data, form.content.data)
        flash('Пост успешно создан!', 'success')
        return redirect(url_for('post_detail', post_id=new_id))

    return render_template('create_post.html', title='Создать пост', form=form, legend='Создать новый пост')


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)

    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Для комментирования необходимо войти.', 'warning')
            return redirect(url_for('login'))

        new_comment = Comment(
            post_id=post_id,
            content=comment_form.content.data,
            user_id=current_user.id
        )
        db.session.add(new_comment)
        db.session.commit()
        log_transaction(post_id, 'COMMENT_CREATE', f'New comment added by User #{current_user.id} to Post #{post_id}.')

        flash('Ваш комментарий добавлен!', 'success')
        return redirect(url_for('post_detail', post_id=post.id))

        # Проверка, является ли текущий пользователь автором поста
    is_author = current_user.is_authenticated and post.author.id == current_user.id

    return render_template('post_detail.html', post=post, is_author=is_author, comment_form=comment_form,
                           current_user=current_user)


@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required  # Только залогиненные
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Проверка прав: только автор может редактировать
    if post.author.id != current_user.id:
        flash('У вас нет прав для редактирования этого поста.', 'danger')
        abort(403)  # 403 Forbidden

    form = PostForm()

    if form.validate_on_submit():
        update_post(post_id, form.title.data, form.content.data)
        flash('Пост успешно обновлен!', 'success')
        return redirect(url_for('post_detail', post_id=post.id))

    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content

    return render_template('create_post.html', title='Редактировать пост', form=form, legend='Редактировать пост')


@app.route('/transactions')
def show_transactions():
    txs = Transaction.query.order_by(Transaction.id.desc()).all()
    return render_template('transactions.html', transactions=txs)


# Удаляем route_add, т.к. теперь посты создаются через /post/new
# Утилітарні маршрути для демонстрації транзакцій (додати/оновити/видалити)
@app.route('/add')
def route_add():
    # Эта функция теперь просто перенаправляет на страницу создания поста
    flash('Перенаправлено на страницу создания поста. Демонстрационный маршрут устарел.', 'warning')
    return redirect(url_for('new_post'))


@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required  # Только залогиненные могут удалять
def route_delete(post_id):
    post = Post.query.get_or_404(post_id)

    # Проверка прав: только автор может удалять
    if post.author.id != current_user.id:
        flash('У вас нет прав для удаления этого поста.', 'danger')
        abort(403)

    ok = delete_post(post_id)
    if ok:
        flash('Пост удален.', 'success')
    else:
        flash('Произошла ошибка при удалении поста.', 'danger')
    return redirect(url_for('show_posts'))


if __name__ == '__main__':
    app.run(debug=True)