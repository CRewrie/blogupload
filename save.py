class Comments(db.Model):
    __tablename__ = "comments"
    comment_id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    users_id = db.Column(db.Integer, ForeignKey('Users.id'))

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