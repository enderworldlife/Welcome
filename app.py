from flask import Flask,render_template,url_for,request,redirect,session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime

app = Flask(__name__)

#Data Base 
#________________________________________

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mydb.db"
app.secret_key = "D-P6rG1w6RO8E40eMjFcAUD_tIuIgAG902e2rP4aDVqah56wmfa0sjyI0LgpJrYw"

db = SQLAlchemy()
db.init_app(app)


class User(db.Model):
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(32), nullable=False, unique=True, index=True)
    nickname = db.Column(db.String(16), nullable=False, unique=True, index=True)
    name = db.Column(db.String(32), nullable=False)
    surname = db.Column(db.String(32), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    admin = db.Column(db.Boolean, default=False)

class Post(db.Model):
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(16), nullable=False)
    text = db.Column(db.Text, nullable=False)
    upload = db.Column(db.String(128), nullable=True)
    user_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(16), nullable=False) 

class Comment(db.Model):
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    upload = db.Column(db.String(128), nullable=True)
    user_id = db.Column(db.Integer, nullable=False)
    post_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(16), nullable=False) 

class Chat(db.Model):
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, nullable=False)
    user2_id = db.Column(db.Integer, nullable=False)

class Message(db.Model):
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)


with app.app_context():
    db.create_all()
#___________________________________________________________________

@app.route('/about')
def about():
    return render_template('./pages/about.html')

#Main
@app.route('/')
def home():
    curent_user = None
    logged = False
    if 'user_id' in session:
        logged = True
        curent_user = User.query.get(session['user_id'])
        

    # logged = 'user_id' in session
    # user = User.query.get(session['user_id'])
    return render_template('./pages/home.html', logged=logged, curent_user=curent_user)
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))
@app.route('/my_profile')
def my_profile():
    user = User.query.get(session['user_id'])
    posts = db.session.query(Post,User).join(User, Post.user_id == User.id).filter(Post.user_id == user.id).order_by(desc(Post.date)).all()
    return render_template('./authentication/my_profile.html', user=user, posts=posts)
@app.route('/profile/<int:id>')
def profile(id):
    user = User.query.get(id)
    posts = db.session.query(Post,User).join(User, Post.user_id == User.id).filter(Post.user_id == id).order_by(desc(Post.date)).all()
    return render_template('./authentication/profile.html', user=user, posts=posts)
@app.route('/admin_users_manager')
def admin_users_manager():
    curent_user = None
    logged = False
    users = db.session.query(User)
    if 'user_id' in session:
        logged = True
        curent_user = User.query.get(session['user_id'])
        if curent_user.admin == 1:
            return render_template('./authentication/admin_users_manager.html',users=users,logged=logged, curent_user=curent_user)
        else:
            return "Aa"

#Post
#_________________________________________________
@app.route('/posts')
def posts():
    curent_user = None
    logged = False
    if 'user_id' in session:
        logged = True
        curent_user = User.query.get(session['user_id'])
    
    
    posts = db.session.query(Post,User).join(User, Post.user_id == User.id).order_by(desc(Post.date)).all()
    return render_template('./pages/posts.html', logged=logged, curent_user=curent_user, posts=posts)
@app.route('/post/<int:id>', methods=["POST", "GET"])
def post(id):
    curent_user = None
    logged = False
    if 'user_id' in session:
        logged = True
        curent_user = User.query.get(session['user_id'])
    if request.method == "POST":
        comment_user = request.form['comment_user']
        comment_post = request.form['comment_post']
        text = request.form['text']
        upload = request.files['photo']
        if upload:
            uploadname = upload.filename
            upload.save(f'static/photos/{uploadname}')
            uploadname = f'static/photos/{uploadname}'
            comment = Comment(text=text,upload=uploadname,user_id=comment_user,post_id=comment_post,date=datetime.datetime.now())
            db.session.add(comment)
            db.session.commit()
        else:
            comment = Comment(text=text,upload=None,user_id=comment_user,post_id=comment_post,date=datetime.datetime.now())
            db.session.add(comment)
            db.session.commit()

    post = Post.query.filter_by(id=id).first()
    user = User.query.filter_by(id=post.user_id).first()

    comments = db.session.query(Comment,User).join(User, Comment.user_id == User.id).filter(Comment.post_id == id).order_by(desc(Comment.date)).all()

    return render_template('./post/post.html', post=post, user=user, id=id, logged=logged, curent_user=curent_user, comments=comments)
    



@app.route('/create_post', methods=["POST", "GET"])
def create_post():
    if 'user_id' not in session:
        redirect('/login')
    else:
        if request.method == "POST":
            title = request.form['title']
            text = request.form['text']
            user_id = session['user_id']
            upload = request.files['photo']
            if upload:
                uploadname = upload.filename
                upload.save(f'static/photos/{uploadname}')
                uploadname = f'static/photos/{uploadname}'
                print(title, text, user_id, uploadname)
                post = Post(title=title,text=text,upload=uploadname,user_id=user_id,date=datetime.datetime.now())
                db.session.add(post)
                db.session.commit()
                return redirect(url_for('posts'))
            else:
                post = Post(title=title,text=text,upload=None,user_id=user_id,date=datetime.datetime.now())
                db.session.add(post)
                db.session.commit()
                return redirect(url_for('posts'))

    return render_template('./post/create_post.html')

@app.route('/delete_post/<int:id>')
def delete_post(id):
    post = Post.query.get(id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('posts'))

@app.route('/delete_comment/<int:id>')
def delete_comment(id):
    comment = Comment.query.get(id)
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('post', id=comment.post_id))

@app.route('/update_post/<int:id>', methods=["POST", "GET"])
def update_post(id):
    post = Post.query.get(id)
    if request.method == "POST":
        post.title = request.form['title']
        post.text = request.form['text']
        upload = request.files['photo']
        uploadname = upload.filename
        upload.save(f'static/photos/{uploadname}')
        uploadname = f'static/photos/{uploadname}'
        post.upload = uploadname

        db.session.commit()
        return redirect(url_for('posts'))
    return render_template('./post/update_post.html', post=post)
        


#Authentication
#_________________________________________________
@app.route('/signup', methods=["POST","GET"])
def signup():
    message = None
    if request.method == "POST":
        email = request.form['email']
        nickname = request.form['nickname']
        name = request.form['name']
        surname = request.form['surname']
        password = request.form['password']
        repeat_password = request.form['repeat_password']
        hashed_password = generate_password_hash(password)
        if not email or not nickname or not name or not surname:
            message = "Not must be empty"
        elif password != repeat_password:
            message = "Passwords not match"
        else:
            if User.query.filter_by(nickname=nickname).first():
                message = "Nickname is not free"
            elif User.query.filter_by(email=email).first():
                message = "Email is not free"
            else:
                if len(password) < 8:
                    message = "Password must be at least 8 characters"
                elif len(nickname) < 3:
                    message = "Nickname must be at least 4 characters"
                elif len(name) < 2 and len(name) < 2:
                    message = "Name and surname must be at least 2 characters"
                elif '@' and '.' not in email:
                    message = "Must be correct email"
                else:
                    user = User(email=email, 
                                nickname=nickname, 
                                name=name, 
                                surname=surname,
                                password=hashed_password)
                    try:
                        db.session.add(user)
                        db.session.commit()
                        session['user_id'] = user.id
                        return redirect(url_for("home"))
                    except Exception as e:
                        return str(e)
                
    return render_template('./authentication/signup.html', message=message)
@app.route('/login', methods=["POST","GET"])
def login():
    message = None
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for("home")) #тут короче должен быть типо зашел в свой аккаунт
        else:
            message = "Uncorrect password or email"
    return render_template('./authentication/login.html', message=message)


#Chats
#___________________________________________
@app.route('/chats')
def chats():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    chats = Chat.query.filter(
        (Chat.user1_id == user_id) |
        (Chat.user2_id == user_id)
    ).all()

    users = []
    for chat in chats:
        if chat.user1_id == user_id:
            users.append(User.query.get(chat.user2_id))
        else:
            users.append(User.query.get(chat.user1_id))

    return render_template('chat/chats.html', users=users)


@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
def chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']

    chat = Chat.query.filter(
        ((Chat.user1_id == current_user_id) & (Chat.user2_id == user_id)) |
        ((Chat.user1_id == user_id) & (Chat.user2_id == current_user_id))
    ).first()

    if not chat:
        chat = Chat(user1_id=current_user_id, user2_id=user_id)
        db.session.add(chat)
        db.session.commit()

    if request.method == 'POST':
        text = request.form['text']
        msg = Message(chat_id=chat.id, sender_id=current_user_id, text=text)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for('chat', user_id=user_id))

    messages = Message.query.filter_by(chat_id=chat.id).order_by(Message.date).all()
    user = User.query.get(user_id)

    return render_template('chat/chat.html', messages=messages, user=user)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)









