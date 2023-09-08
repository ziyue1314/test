from fastapi import FastAPI, HTTPException, Header
import uvicorn

from pydantic import BaseModel


# 通过Pydantic模型来定义user
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str


# 使用 SQLAlchemy 来创建对应的数据库模型，并与 SQLite 数据库进行连接。
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import declarative_base
# 连接sqlite
# 创建数据库引擎
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
# 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# 创建 SQLAlchemy 的基类（Base class）
Base = declarative_base()


# 创建User的数据库模型类
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)


# 用户注册
from passlib.hash import bcrypt
# 用户登录
from fastapi import Depends
from sqlalchemy.orm import Session
from jwt import decode as jwt_decode
from datetime import datetime, timedelta


# 身份验证和访问令牌相关的常量或配置选项
# 密钥：这是用于签署和验证访问令牌的秘密密钥
SECRET_KEY = "5J7dM@K#v&*aH9W^S!pX"
# 算法：用于生成和验证访问令牌的签名算法   HS256 表示 HMAC-SHA256 算法，它将密钥与令牌数据进行散列并生成签名
ALGORITHM = "HS256"
# 令牌过期时间
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# 用户信息验证
from jwt import PyJWTError
# 错误处理
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# 用户注册
@app.post("/users/")
def creat_user(user: UserCreate):
    db = SessionLocal()
    # 检查用户名和邮箱是否已存在
    existing_user = db.query(User).filter_by(username=user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    existing_email = db.query(User).filter_by(email=user.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    # 创建新用户并保存到数据库
    hashed_password = bcrypt.hash(user.password)
    db_user = User(username=user.username, email=user.email, full_name=user.full_name, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"message": "User created successfully"}


# 用户登录

# 获取数据库会话对象的函数
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/token")
def login_user(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=username).first()

    if not user or not bcrypt.verify(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token_data = {
        "sub": user.username,
        "exp": datetime.utcnow() + access_token_expires
    }

    access_token = jwt_decode(access_token_data, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": access_token, "token_type": "bearer"}


# 用户信息验证
def get_token(auth_header: str = Header(...)):
    if auth_header.startswith("Bearer "):
        token = auth_header.split("Bearer ")[1]
        return token
    raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/users/me/")
def get_user_profile(token: str = Depends(get_token), db: Session = Depends(get_db)):
    try:
        # jwt_decode()  token：要解码的 JWT 字符串; SECRET_KEY：用于验证 JWT 的密钥; algorithms：用于指定 JWT 签名算法的列表
        payload = jwt_decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user = db.query(User).filter_by(username=username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return {"username": user.username, "email": user.email, "full_name": user.full_name}
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# 当用户提供了无效的凭证（用户名或密码错误）时
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(status_code=400, content={"detail": "Validation error"})


# 2. 当用户尝试访问需要令牌的路由但未提供令牌或提供了无效的令牌时
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

"""
实现用户密码的重置功能:
1.用户请求重置密码。
2.生成一个包含重置密码令牌的链接，并将其发送给用户。
3.用户点击链接，跳转到一个路由 /reset-password/{token}。
4.检查令牌是否有效，并验证用户身份。
5.如果令牌有效且用户身份验证成功，则允许用户输入新密码并重置密码。
"""

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8080)
