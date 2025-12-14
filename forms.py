from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError


# ВАЖНО: УДАЛЕН ИМПОРТ 'from app import User' ВО ИЗБЕЖАНИЕ ЦИКЛИЧЕСКОЙ ЗАВИСИМОСТИ

# ======================================================================
# Формы для Постов и Комментариев
# ======================================================================

class PostForm(FlaskForm):
    title = StringField('Заголовок поста', validators=[DataRequired(), Length(min=5, max=100)])
    content = TextAreaField('Содержание поста', validators=[DataRequired()])
    submit = SubmitField('Сохранить изменения')


class CommentForm(FlaskForm):
    content = TextAreaField('Написать комментарий', validators=[DataRequired(), Length(min=2, max=500)])
    submit = SubmitField('Отправить комментарий')


# ======================================================================
# ФОРМЫ ДЛЯ АУТЕНТИФИКАЦИИ
# ======================================================================

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Подтвердите пароль',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message='Пароли должны совпадать')])

    # Поля для заполнения данных пользователя
    name = StringField('Имя', validators=[DataRequired()])
    surname = StringField('Фамилия', validators=[DataRequired()])
    group = StringField('Группа', validators=[DataRequired()])

    submit = SubmitField('Зарегистрироваться')

    # Пользовательские валидаторы для проверки уникальности
    def validate_username(self, username):
        # ИМПОРТ ВНУТРИ ФУНКЦИИ + ИМПОРТ app!
        from app import app, User

        # Активация контекста приложения
        with app.app_context():
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Это имя пользователя уже занято. Пожалуйста, выберите другое.')

    def validate_email(self, email):
        # ИМПОРТ ВНУТРИ ФУНКЦИИ + ИМПОРТ app!
        from app import app, User

        # Активация контекста приложения
        with app.app_context():
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Этот email уже зарегистрирован. Пожалуйста, используйте другой.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')