from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, selectinload
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateCommentForm
from flask_gravatar import Gravatar
from wtforms import SubmitField, BooleanField, StringField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from flask_wtf import Form
import requests
from flask_login import LoginManager
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
import os



app = Flask(__name__)
#app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6c'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


class Comments(db.Model):
    __tablename__ = "comments"
    comment_id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    users_id = db.Column(db.Integer, ForeignKey('Users.id'))
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    users_id = db.Column(db.Integer, ForeignKey('Users.id'))
    comments = relationship(Comments)


class Users(db.Model, UserMixin):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship(BlogPost)
    comments = relationship(Comments)

db.create_all()

class RegisterForm(Form):
    email = EmailField('Enter Email', validators=[validators.Email(), validators.DataRequired()])
    password = PasswordField('Enter Password', validators=[validators.DataRequired()])
    name = StringField('Enter Username', validators=[validators.DataRequired()])
    submit_button = SubmitField('Register')

class LoginForm(Form):
    email = EmailField('Enter Email', validators=[validators.Email(), validators.DataRequired()])
    password = PasswordField('Enter Password', validators=[validators.DataRequired()])
    submit_button = SubmitField('LetMeIn!')


@app.errorhandler(403)
def resource_not_found(e):
    return jsonify(error=str(e)), 403

def admin(f):
    @wraps(f)
    def admin_auth(*args, **kwargs):
        if current_user.get_id() != "1":
            abort(403, description="Admin only.")
        return f(*args, **kwargs)
    return admin_auth

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate_on_submit():
        registered = db.session.query(Users).filter_by(email=form.email.data).first()
        if not registered == None:
            loginform = LoginForm(request.form)
            flash("You are already registered, please login.")
            return redirect(url_for("login", form=loginform))
        else:
            new_user = Users(
                email=form.email.data,
                password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8),
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            user = db.session.query(Users).filter_by(email=form.email.data).first()
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    loginform = LoginForm(request.form)
    if request.method == "POST" and loginform.validate_on_submit():
        user = db.session.query(Users).filter_by(email=loginform.email.data).first()
        if user == None:
            flash("This Email does not exist")
            return redirect(url_for("login", form=loginform))
        elif not check_password_hash(user.password, loginform.password.data):
            flash("The entered password is incorrect.")
            return redirect(url_for("login", form=loginform))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=loginform)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    commentform = CreateCommentForm(request.form)
    requested_post = BlogPost.query.get(post_id)

    #comments = db.session.query(Comments).filter_by(post_id=post_id).all()
    #comments2 = db.session.query(Comments).join(Users).filter(Comments.post_id==post_id).all()
    #test = db.session.query(Users).options(selectinload(Users.posts)).all()
    comments = db.session.query(Comments, Users).join(Users).filter(Comments.post_id==post_id).all()
    if request.method == "POST" and commentform.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comments(
                post_id=int(post_id),
                users_id=int(current_user.get_id()),
                text=commentform.body.data,
                date=date.today().strftime("%B %d, %Y"),
            )
            db.session.add(new_comment)
            db.session.commit()
            comments = db.session.query(Comments, Users).join(Users).filter(Comments.post_id == post_id).all()
            return render_template("post.html", post=requested_post, comments=comments, form=commentform)
        else:
            flash("Please login first before commenting.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, comments=comments, form=commentform)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            users_id=int(current_user.get_id())
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/deletec/<int:comment_id>")
@admin
def delete_comment(comment_id):
    comment_to_delete = Comments.query.get(comment_id)
    post_id = comment_to_delete.post_id
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
