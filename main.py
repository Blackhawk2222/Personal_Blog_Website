from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash,request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import smtplib
import os
# Import your forms from the forms.py
from forms import CreatePostForm,Register_user,Login_user,Comment


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

EMAIL="testingpython896@gmail.com"
PASSWORD="sqpbsfxfwedgufwx"
TO="pythontestsender445@gmail.com"

app = Flask(__name__)
app.config['SECRET_KEY'] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager=LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author=relationship('User',back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comment = relationship('Comments', back_populates='parent_post')

# TODO: Create a User table for all your registered users. 
class User(db.Model,UserMixin):
    __tablename__="users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100),nullable=False)
    name = db.Column(db.String(1000),nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comment=relationship('Comments',back_populates='comment_author')

class Comments(db.Model):
    __tablename__="comments"
    id=db.Column(db.Integer,primary_key=True)
    author_id=db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author=relationship('User',back_populates='comment')
    blog_id=db.Column(db.Integer,db.ForeignKey('blog_posts.id'))
    parent_post=relationship('BlogPost',back_populates='comment')
    text=db.Column(db.Text,nullable=False)


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods=["GET","POST"])
def register():
    meth=request.method
    if meth=="POST":
        email = request.form.get("email")
        existing = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if existing:
            flash("You have already registered with this email.Log in instead")
            return redirect(url_for("login"))
        pasw=generate_password_hash(password=request.form.get("password"),method="pbkdf2:sha256",salt_length=8)
        new_user=User(email=email,password=pasw,name=request.form.get("name"))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts",logged_in=current_user.is_authenticated,id=new_user.id))
    else:
        form=Register_user()
        return render_template("register.html",form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login',methods=["GET","POST"])
def login():
    meth=request.method
    if meth=="POST":
        email=request.form.get("email")
        existing=db.session.execute(db.select(User).where(User.email==email)).scalar()
        if existing:
            current_password=existing.password
            entered_password=request.form.get("password")
            if check_password_hash(pwhash=current_password,password=entered_password):
                login_user(existing)
                return redirect(url_for("get_all_posts",logged_in=current_user.is_authenticated))
            else:
                flash("Wrong Password")
                return redirect(url_for("login"))
        else:
            flash("Email not registered")
            return redirect(url_for("login"))
    else:
        form=Login_user()
        return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts',logged_in=False))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    posts.reverse()
    return render_template("index.html", all_posts=posts, current_user=current_user)

# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    meth=request.method
    if meth=="POST":
        if current_user.is_authenticated:
            requested_post=db.get_or_404(BlogPost,post_id)
            new_comment=Comments(text=request.form.get("comment"),parent_post=requested_post,comment_author=current_user)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post",post_id=post_id))
        else:
            flash("You need to be logged in to post a comment")
            return redirect(url_for('login'))
    else:
        all_comments=db.session.execute(db.select(Comments).where(Comments.blog_id==post_id)).scalars().all()
        form=Comment()
        requested_post = db.get_or_404(BlogPost, post_id)
        return render_template("post.html", post=requested_post,form=form,comments=all_comments)


# TODO: Use a decorator so only an admin user can create a new post

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact",methods=["GET","POST"])
def contact():
    meth = request.method
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        message = request.form["message"]
        k = f"Subject:Blog message\n\nName : {name}\nEmail : {email}\nPhone number : {phone}\nMessage : {message}"
        k = k.encode('utf-8')
        with smtplib.SMTP("smtp.gmail.com") as sm:
            sm.starttls()
            sm.login(user=EMAIL, password=PASSWORD)
            sm.sendmail(from_addr=EMAIL, to_addrs=TO, msg=k)

        return render_template("contact.html", data=meth)
    elif request.method == "GET":
        return render_template("contact.html", data=meth)

@app.route("/author_profile")
def author_profile():
    return render_template("author_profile.html")



if __name__ == "__main__":
    app.run(debug=False, port=5002)
