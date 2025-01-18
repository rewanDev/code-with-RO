from flask import Flask, render_template, url_for, flash, redirect, request
from PIL import Image
import os, secrets
from itsdangerous import URLSafeTimedSerializer as Serializer
from markupsafe import Markup
from flask_ckeditor import CKEditor
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditorField
from flask import (
    render_template,
    url_for,
    flash,
    redirect,
    request,
    session,
    abort,
    send_from_directory,
)
from flask_wtf import FlaskForm
from tokenize import String
from flask_migrate import Migrate
from flask_wtf.file import FileField, FileAllowed
from flask_bcrypt import Bcrypt
from flask_login import (
    login_required,
    login_user,
    current_user,
    LoginManager,
    logout_user,
    UserMixin,
)
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, ValidationError
from wtforms_sqlalchemy.fields import QuerySelectField
from datetime import datetime
# Main app initialization
app = Flask(__name__)
app.config["SECRET_KEY"] = "13f26d0c4b78b463dd95f692e4965ce5298b2bf174ef12ae2f083b8d6a925d4b"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pythonic.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Defining db after app initialization to avoid circular import
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
ckeditor = CKEditor(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
app.config["MAIL_SERVER"] = "smtp.googlemail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("rewan.developer@gmail.com")
app.config["MAIL_PASSWORD"] = os.environ.get("ktbd qiuy zmmz oseh")
mail = Email(app)

# Dummy Data
lessons = [
    {
        "title": "Request Library Course",
        "course": "Python",
        "author": "Omar",
        "thumbnail": "thumbnail.jpg",
    },
    # Other lessons here...
]

courses = [
    {
        "name": "Python",
        "icon": "python.svg",
        "description": "Lorem ipsum dolor sit amet consectetur adipisicing elit. Neque quidem nihil dolor officiis at magni!",
    },
    # Other courses here...
]

# Models
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(25), nullable=False)
    lname = db.Column(db.String(25), nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(125), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default="default.png")
    bio = db.Column(db.Text, nullable=True)
    password = db.Column(db.String(60), nullable=False)
    lessons = db.relationship("Lesson", backref="author", lazy=True)

    def get_reset_token(self):
        s = Serializer(app.config['SECRET_KEY'], salt='pw-reset')
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, age=3600):
        s = Serializer(app.config['SECRET_KEY'], salt='pw-reset')
        try:
            user_id = s.loads(token, max_age=age)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.fname}', '{self.lname}', '{self.username}', '{self.email}', '{self.image_file}')"

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    thumbnail = db.Column(
        db.String(20), nullable=False, default="default_thumbnail.jpg"
    )
    slug = db.Column(db.String(32), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)

    def __repr__(self):
        return f"Lesson('{self.title}', '{self.date_posted}')"


class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(150), nullable=False)
    icon = db.Column(db.String(20), nullable=False, default="default_icon.jpg")
    lessons = db.relationship("Lesson", backref="course_name", lazy=True)

    def __repr__(self):
        return f"Course('{self.title}')"

# Forms
class RegistrationForm(FlaskForm):
    fname = StringField(
        "First Name", validators=[DataRequired(), Length(min=2, max=25)]
    )
    lname = StringField("Last Name", validators=[DataRequired(), Length(min=2, max=25)])
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=25)]
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Regexp(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_])[A-Za-z\d@$!%*?&_]{8,32}$"
            ),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                "Username already exists! Please chosse a different one"
            )

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("Email already exists! Please chosse a different one")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
        ],
    )
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")


class UpdateProfileForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=25)]
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    bio = TextAreaField("Bio")
    picture = FileField(
        "Update Profile Picture", validators=[FileAllowed(["jpg", "png"])]
    )
    submit = SubmitField("Update")

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    "Username already exists! Please chosse a different one"
                )

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError(
                    "Email already exists! Please chosse a different one"
                )


def choice_query():
    return Course.query

class NewLessonForm(FlaskForm):
    course = QuerySelectField("Course", query_factory=choice_query, get_label="title")
    title = StringField("Lesson Title", validators=[DataRequired(), Length(max=100)])
    slug = StringField(
        "Slug",
        validators=[DataRequired(), Length(max=32)],
        render_kw={
            "placeholder": "Descriptive short version of your title. SEO friendly"
        },
    )
    content = CKEditorField(
        "Lesson Content", validators=[DataRequired()], render_kw={"rows": "20"}
    )
    thumbnail = FileField(
        "Thumbnail", validators=[DataRequired(), FileAllowed(["jpg", "png"])]
    )
    submit = SubmitField("Post")


class NewCourseForm(FlaskForm):
    title = StringField("Course Name", validators=[DataRequired(), Length(max=50)])
    description = TextAreaField(
        "Course Description", validators=[DataRequired(), Length(max=150)]
    )
    icon = FileField("Icon", validators=[DataRequired(), FileAllowed(["jpg", "png"])])
    submit = SubmitField("Create")

    def validate_title(self, title):
        course = Course.query.filter_by(title=title.data).first()
        if course:
            raise ValidationError(
                "Course name already exists! Please choose a different one"
            )


class LessonUpdateForm(NewLessonForm):
    thumbnail = FileField("Thumbnail", validators=[FileAllowed(["jpg", "png"])])
    submit = SubmitField("Update")


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Regexp(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_])[A-Za-z\d@$!%*?&_]{8,32}$"
            ),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Reset Password")


def save_picture(form_picture, path, output_size=None):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_name = random_hex + f_ext
    picture_path = os.path.join(app.root_path, path, picture_name)
    i = Image.open(form_picture)
    if output_size:
        i.thumbnail(output_size)
    i.save(picture_path)
    return picture_name


def get_previous_next_lesson(lesson):
    course = lesson.course_name
    for lsn in course.lessons:
        if lsn.title == lesson.title:
            index = course.lessons.index(lsn)
            previous_lesson = course.lessons[index - 1] if index > 0 else None
            next_lesson = (
                course.lessons[index + 1] if index < len(course.lessons) - 1 else None
            )
            break
    return previous_lesson, next_lesson


def delete_picture(picture_name, path):
    picture_path = os.path.join(app.root_path, path, picture_name)
    try:
        os.remove(picture_path)
    except:
        pass


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message(
        "Pythonic App Password Reset Request",
        sender="rewan.developer@gmail.com",
        recipients=[user.email],
        body=f"""To reset your password, visit the following link:
        {url_for('reset_password', token=token, _external=True)}
        
        if you did not make this request, please ignore this email.""",
    )
    mail.send(msg)


# Routes
@app.route("/")
@app.route("/home")
def home():
    lessons = Lesson.query.all()
    courses = Course.query.all()
    return render_template("home.html", lessons=lessons, courses=courses)


@app.route("/about")
def about():
    return render_template("about.html", title="About")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user = User(
            fname=form.fname.data,
            lname=form.lname.data,
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
        )
        db.session.add(user)
        db.session.commit()
        flash(f"Account created successfully for {form.username.data}", "success")
        return redirect(url_for("login"))
    return render_template("register.html", title="Register", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get("next")
            flash("You have been logged in!", "success")
            return redirect(next_page) if next_page else redirect(url_for("home"))
        else:
            flash("Login Unsuccessful. Please check credentials", "danger")
    return render_template("login.html", title="Login", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    return render_template("dashboard.html", title="Dashboard", active_tab=None)


@app.route("/dashboard/profile", methods=["GET", "POST"])
@login_required
def profile():
    profile_form = UpdateProfileForm()
    if profile_form.validate_on_submit():
        if profile_form.picture.data:
            picture_file = save_picture(
                profile_form.picture.data, "static/user_pics", output_size=(150, 150)
            )
            current_user.image_file = picture_file
        current_user.username = profile_form.username.data
        current_user.email = profile_form.email.data
        current_user.bio = profile_form.bio.data
        db.session.commit()
        flash("Your profile has been updated", "success")
        return redirect(url_for("profile"))
    elif request.method == "GET":
        profile_form.username.data = current_user.username
        profile_form.email.data = current_user.email
        profile_form.bio.data = current_user.bio
    image_file = url_for("static", filename=f"user_pics/{current_user.image_file}")
    return render_template(
        "profile.html",
        title="Profile",
        profile_form=profile_form,
        image_file=image_file,
        active_tab="profile",
    )


@app.route("/dashboard/new_lesson", methods=["GET", "POST"])
@login_required
def new_lesson():
    new_lesson_form = NewLessonForm()
    new_course_form = NewCourseForm()
    form = ""
    flag = session.pop("flag", False)
    if "content" in request.form:
        form = "new_lesson_form"
    elif "description" in request.form:
        form = "new_course_form"

    if form == "new_lesson_form" and new_lesson_form.validate_on_submit():
        if new_lesson_form.thumbnail.data:
            picture_file = save_picture(
                new_lesson_form.thumbnail.data, "static/lesson_thumbnails"
            )
        lesson_slug = str(new_lesson_form.slug.data).replace(" ", "-")
        course = new_lesson_form.course.data
        lesson = Lesson(
            title=new_lesson_form.title.data,
            content=new_lesson_form.content.data,
            slug=lesson_slug,
            author=current_user,
            course_name=course,
            thumbnail=picture_file,
        )
        db.session.add(lesson)
        db.session.commit()
        flash("Your lesson has been created!", "success")
        return redirect(url_for("new_lesson"))

    elif form == "new_course_form" and new_course_form.validate_on_submit():
        if new_course_form.icon.data:
            picture_file = save_picture(
                new_course_form.icon.data, "static/course_icons", output_size=(150, 150)
            )
        course_title = str(new_course_form.title.data).replace(" ", "-")
        course = Course(
            title=course_title,
            description=new_course_form.description.data,
            icon=picture_file,
        )
        db.session.add(course)
        db.session.commit()
        session["flag"] = True
        flash("New Course has been created!", "success")
        return redirect(url_for("dashboard"))

    modal = None if flag else "newCourse"
    return render_template(
        "new_lesson.html",
        title="New Lesson",
        new_lesson_form=new_lesson_form,
        new_course_form=new_course_form,
        active_tab="new_lesson",
    )


@app.route("/<string:course>/<string:lesson_slug>")
def lesson(lesson_slug, course):
    lesson = Lesson.query.filter_by(slug=lesson_slug).first()
    if lesson:
        previous_lesson, next_lesson = get_previous_next_lesson(lesson)
    lesson_id = lesson.id if lesson else None
    lesson = Lesson.query.get_or_404(lesson_id)
    return render_template(
        "lesson.html",
        title=lesson.title,
        lesson=lesson,
        previous_lesson=previous_lesson,
        next_lesson=next_lesson,
    )


@app.route("/<string:course_title>")
def course(course_title):
    course = Course.query.filter_by(title=course_title).first()
    course_id = course.id if course else None
    course = Course.query.get_or_404(course_id)
    return render_template(
        "course.html",
        title=course.title,
        course=course,
    )


@app.route("/courses")
def courses():
    courses = Course.query.all()
    return render_template("courses.html", title="Courses", courses=courses)

@app.route("/dashboard/user_lessons", methods=["GET", "POST"])
@login_required
def user_lessons():
    return render_template(
        "user_lessons.html", title="Your Lessons", active_tab="user_lessons"
    )


@app.route("/<string:course>/<string:lesson_slug>/update", methods=["GET", "POST"])
def update_lesson(lesson_slug, course):
    lesson = Lesson.query.filter_by(slug=lesson_slug).first()
    if lesson:
        previous_lesson, next_lesson = get_previous_next_lesson(lesson)
    lesson_id = lesson.id if lesson else None
    lesson = Lesson.query.get_or_404(lesson_id)
    if lesson.author != current_user:
        abort(403)
    form = LessonUpdateForm()
    if form.validate_on_submit():
        lesson.course_name = form.course.data
        lesson.title = form.title.data
        lesson.slug = str(form.slug.data).replace(" ", "-")
        lesson.content = form.content.data
        if form.thumbnail.data:
            delete_picture(lesson.thumbnail, "static/lesson_thumbnails")
            new_picture = save_picture(form.thumbnail.data, "static/lesson_thumbnails")
            lesson.thumbnail = new_picture
        db.session.commit()
        flash("Your lesson has been updated!", "success")
        return redirect(
            url_for("lesson", lesson_slug=lesson.slug, course=lesson.course_name.title)
        )
    elif request.method == "GET":
        form.course.data = lesson.course_name.title
        form.title.data = lesson.title
        form.slug.data = lesson.slug
        form.content.data = lesson.content
    return render_template(
        "update_lesson.html",
        title="Update | " + lesson.title,
        lesson=lesson,
        previous_lesson=previous_lesson,
        next_lesson=next_lesson,
        form=form,
    )




@app.route("/lesson/<lesson_id>/delete", methods=["POST"])
def delete_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    if lesson.author != current_user:
        abort(403)
    db.session.delete(lesson)
    db.session.commit()
    flash("Your lesson has been deleted!", "success")
    return redirect(url_for("user_lessons"))

@app.route("/reset_password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash(
            "If this account exists, you will receive an email with instructions",
            "info",
        )
        return redirect(url_for("login"))
    return render_template("reset_request.html", title="Reset Password", form=form)


@app.route("/author/<string:username>", methods=["GET"])
def author(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get("page", 1, type=int)
    lessons = (
        Lesson.query.filter_by(author=user)
        .order_by(Lesson.date_posted.desc())
        .paginate(page=page, per_page=6)
    )
    return render_template("author.html", lessons=lessons, user=user)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    user = User.verify_reset_token(token)
    if not user:
        flash("The token is invalid or expired", "warning")
        return redirect(url_for("reset_request"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user.password = hashed_password
        db.session.commit()
        flash(f"Your password has been updated. You can now log in", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", title="Reset Password", form=form)

if __name__ == "__main__":
    app.run(debug=True)
