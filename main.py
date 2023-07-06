# import libraries
from fastapi import FastAPI, HTTPException, Depends, status
from typing import List, Optional
from jose import JWTError, jwt
from pydantic import BaseModel
from datetime import datetime, timedelta
from passlib.context import CryptContext
from database import SessionLocal
from database import User, Post, Like
from decouple import config

# Generate crypto-context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# metadata for swagger
tags_metadata = [
    {
        "name": "Sign up",
        "description": "Sign up. Creates a new user account.",
    },
    {
        "name": "Login",
        "description": "Create JWT after validating username and password for a user.",
    },
    {
        "name": "Posts",
        "description": "Managing posts: GET all posts, CREATE post, EDIT post, DELETE post",
    },
    {
        "name": "Likes",
        "description": "Managing posts: LIKE post (or change from dislike to like), DISLIKE post (or change from like to dislike), UNLIKE post (remove any rating)",
    }
]

# Create main app
app = FastAPI(openapi_tags=tags_metadata, docs_url="/")


@app.post("/signup", tags=['Sign up'])
def signup(username: str, password: str):
    """
    POST-request.\n
    Sign up function which create new user account.\n
    Parameters: \n
            username: str \n
            password to create account: str\n
    Returns: \n
             200 OK and message: Signup successful\n
             500 and message: This username is taken if username already in database
    """
    # create database session context
    db = SessionLocal()
    # Create user account or raises HTTPException on existing in database username
    try:
        user = User(username=username, hashed_password=pwd_context.hash(password))
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"message": "Signup successful"}
    except Exception:
        raise HTTPException(status_code=500, detail="This username is taken")


@app.post("/login", tags=['Login'])
def login(username: str, password: str):
    """
        POST-request.\n
        Login function which create jw token.
        Parameters: \n
                username: str \n
                password to login: str. Password in database is hashed\n
        Returns: \n
                 200 OK and access_token
                 401 and message: Invalid username or password
        """
    # create database session context
    db = SessionLocal()
    # Get user from database by username
    user = get_user_by_username(username, db)
    # verify inputted password with hashed in database and raise Exception if it is wrong
    if not user or not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {"access_token": create_access_token({"user_id": user.user_id})}


@app.get("/posts", tags=["Posts"])
def get_posts():
    """
            GET-request.\n
            Get all posts with rating.\n
            Returns: \n
                     200 OK and all posts from database
            """
    # create database session context
    db = SessionLocal()
    # dict for send posts to a user
    posts_to_send = {}
    # database query to get all posts
    posts = db.query(Post).all()
    for post in posts:
        # get all likes and dislikes to the post and bind them with post
        likes = db.query(Like).filter(Like.post_id == post.post_id, Like.type == "like").all()
        dislikes = db.query(Like).filter(Like.post_id == post.post_id, Like.type == "dislike").all()
        posts_to_send.update({
            "content": post.content,
            "post_id": post.post_id,
            "user_id": post.user_id,
            "likes": likes,
            "dislikes": dislikes
        })
    return posts_to_send


@app.post("/posts", tags=["Posts"])
def create_post(content: str, token: str):
    """
            POST-request.\n
            Creating new post. \n
            Parameters: \n
                    content of a new post: str \n
                    jw-token: str \n
            Returns: \n
                     200 OK and message: Post created successfully\n
                     401 and message: Invalid token
    """
    # create database session context
    db = SessionLocal()
    # get user from database by token
    user = get_user_by_token(token, db)
    # raise exception if user wrong token
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    # store new post in database
    post = Post(user_id=user.user_id, content=content)
    db.add(post)
    db.commit()
    db.refresh(post)
    return {"message": "Post created successfully"}


@app.put("/posts/{post_id}", tags=["Posts"])
def edit_post(post_id: int, content: str, token: str):
    """
            PUT-request.\n
            Editing existing post function.\n
            Parameters: \n
                    content of a new post: str \n
                    jw-token of a user: str \n
                    existing post_id which needs to be changed: integer \n
            Returns: \n
                     200 OK and message: Post updated successfully\n
                     401 and message: Invalid token\n
                     404 and message: Post not found or unauthorized or it isn't your post
    """
    # create database session context
    db = SessionLocal()
    # get user from database by token
    user = get_user_by_token(token, db)
    # raise exception if wrong token
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # get post from database by id
    post = get_post_by_id(post_id, db)
    # raise exception if user isn't creator of this post
    if not post or post.user_id != user.user_id:
        raise HTTPException(status_code=404, detail="Post not found or unauthorized or it isn't your post")
    # updating content of the post
    post.content = content
    db.commit()
    db.refresh(post)
    return {"message": "Post updated successfully"}


@app.delete("/posts/{post_id}", tags=["Posts"])
def delete_post(post_id: int, token: str):
    """
                DELETE-request.\n
                Deleting existing post function.\n
                Parameters: \n
                        jw-token of a user: str \n
                        existing post_id which needs to be deleted: integer \n
                Returns: \n
                         200 OK and message: Post deleted successfully\n
                         401 and message: Invalid token\n
                         404 and message: Post not found or unauthorized or it isn't your post
        """
    # create database session context
    db = SessionLocal()
    # get user from database by token
    user = get_user_by_token(token, db)
    # raise exception if wrong token
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # get post from database by id
    post = get_post_by_id(post_id, db)
    # raise exception if user isn't creator of this post
    if not post or post.user_id != user.user_id:
        raise HTTPException(status_code=404, detail="Post not found or unauthorized or it isn't your post")

    # delete post from database
    delete_likes(post.post_id, db)
    db.delete(post)
    db.commit()
    return {"message": "Post deleted successfully"}


@app.post("/posts/{post_id}/like", tags=["Likes"])
def like_post(post_id: int, token: str):
    """
            POST-request.\n
            Rating function.\n
            Parameters: \n
                    jw-token of a user: str \n
                    existing post_id which needs to be liked: integer \n
            Returns: \n
                     200 OK and message: Post liked successfully\n
                     200 OK and message: Post liked already\n
                     400 and message: Cannot like your own post\n
                     401 and message: Invalid token\n
                     404 and message: Post not found
    """
    # create database session context
    db = SessionLocal()
    # get user from database by token
    user = get_user_by_token(token, db)
    # raise exception if wrong token
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # get post from database by id
    post = get_post_by_id(post_id, db)
    # raise exception if post doesn't found by this id
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # raise exception if user is creator of this post
    if post.user_id == user.user_id:
        raise HTTPException(status_code=400, detail="Cannot like your own post")

    # Checking if like changes dislike or already liked
    like = get_like_by_user_and_post(user.user_id, post.post_id, db)
    if not like:
        like = Like(user_id=user.user_id, post_id=post.post_id, type="like")
        db.add(like)
        db.commit()
        db.refresh(like)
    elif like.type == "like":
        return {"message": "Post liked already"}
    elif like.type == "dislike":
        like.type = "like"
        db.commit()
        db.refresh(like)

    return {"message": "Post liked successfully"}


@app.post("/posts/{post_id}/dislike", tags=["Likes"])
def dislike_post(post_id: int, token: str):
    """
              POST-request.\n
              Rating function. \n
              Parameters: \n
                      jw-token of a user: str \n
                      existing post_id which needs to be disliked: integer \n
              Returns: \n
                       200 OK and message: Post disliked successfully\n
                       200 OK and message: Post disliked already\n
                       400 and message: Cannot disliked your own post\n
                       401 and message: Invalid token\n
                       404 and message: Post not found
      """
    # create database session context
    db = SessionLocal()

    # get user from database by token
    user = get_user_by_token(token, db)
    # raise exception if wrong token
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # get post from database by id
    post = get_post_by_id(post_id, db)
    # raise exception if post doesn't found by this id
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # raise exception if user is creator of this post
    if post.user_id == user.user_id:
        raise HTTPException(status_code=400, detail="Cannot dislike your own post")

    # Checking if dislike changes like or already disliked
    like = get_like_by_user_and_post(user.user_id, post.post_id, db)
    if not like:
        like = Like(user_id=user.user_id, post_id=post.post_id, type="dislike")
        db.add(like)
        db.commit()
        db.refresh(like)
    elif like.type == "dislike":
        return {"message": "Post disliked already"}
    elif like.type == "like":
        like.type = "dislike"
        db.commit()
        db.refresh(like)

    return {"message": "Post disliked successfully"}


@app.post("/posts/{post_id}/unlike", tags=["Likes"])
def unlike_post(post_id: int, token: str):
    """
         POST-request.\n
         Rating function. \n
         Parameters: \n
                 jw-token of a user: str \n
                 existing post_id which needs to be unliked: integer \n
         Returns: \n
                  200 OK and message: Post unliked successfully\n
                  200 OK and message: Post unliked already\n
                  400 and message: Cannot unliked your own post\n
                  401 and message: Invalid token\n
                  404 and message: Post not found
         """
    # create database session context
    db = SessionLocal()

    # get user from database by token
    user = get_user_by_token(token, db)
    # raise exception if wrong token
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # get post from database by id
    post = get_post_by_id(post_id, db)
    # raise exception if post doesn't found by this id
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # raise exception if user is creator of this post
    if post.user_id == user.user_id:
        raise HTTPException(status_code=400, detail="Cannot like your own post")

    # delete rating from database
    like = get_like_by_user_and_post(user.user_id, post_id, db)
    if like:
        db.delete(like)
        db.commit()
    return {"message": "Post unliked successfully"}


# delete all ratings whe post deleted
def delete_likes(post_id, db):
    likes = db.query(Like).filter(Like.post_id == post_id).all()
    for like in likes:
        db.delete(like)
        db.commit()
    return


# get user from database by username
def get_user_by_username(username: str, db):
    user = db.query(User).filter(User.username == username).first()
    return user


# get user from database by token
def get_user_by_token(token: str, db):
    try:
        # try to decode the token, it will
        # raise error if the token is not correct
        payload = jwt.decode(token, config("SECRET_KEY"), algorithms=[config("ALGORITHM")])
        user = db.query(User).filter(User.user_id == payload['user_id']).first()
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


# get post from database by id
def get_post_by_id(post_id: int, db):
    return db.query(Post).filter(Post.post_id == post_id).first()


# get all ratings of some post from database by post id
def get_like_by_user_and_post(user_id: int, post_id: int, db):
    return db.query(Like).filter(Like.user_id == user_id, Like.post_id == post_id).first()


# this function will create the token
# for particular data
def create_access_token(data: dict):
    to_encode = data.copy()

    # expire time of the token
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, config("SECRET_KEY"), algorithm=config("ALGORITHM"))

    # return the generated token
    return encoded_jwt
