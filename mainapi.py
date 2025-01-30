from fastapi import FastAPI,Request, status
from sqlalchemy.orm import Session,column_property
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI,Response,status,HTTPException,Depends, APIRouter
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from typing import List
from sqlalchemy import func
from sqlalchemy.sql import text
import sqlalchemy as bb
from mangum import Mangum
from jose import JWTError,jwt
from datetime import datetime, timedelta
from fastapi import Depends,status,HTTPException
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme= OAuth2PasswordBearer(tokenUrl='login')
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from pydantic import BaseSettings
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import psycopg2
import psycopg2.extras 
from psycopg2.extras  import RealDictCursor
import time
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.sql.sqltypes import TIMESTAMP, DATE
from sqlalchemy.sql.expression import text
from sqlalchemy import func
from sqlalchemy.orm import column_property
from pydantic import BaseModel, validator
from datetime import date,datetime
from typing import Optional
from pydantic.types import conint
from passlib.hash import pbkdf2_sha256






engine= create_engine('mysql+pymysql://arjangillmain:gill12391@p3nlmysql77plsk.secureserver.net:3306/ph16873094761_', pool_recycle=3600)

sessionlocal= sessionmaker(autocommit=False, autoflush=False, bind=engine)

base= declarative_base()

def get_db(): # TO GET CONNECTION TO DATABASE
   db= sessionlocal()
   try:
      yield db
   finally:
      db.close()
 


class Income(base):
    __tablename__="income"
    
    id= Column(Integer,primary_key=True,nullable=False)
    is_deleted=Column(String,nullable=False,server_default='f')
    user_id=Column(Integer,nullable=False)
    clinet_id=Column(Integer, nullable=False)
    dates=Column(DATE, nullable=False)
    type_val=Column(Integer,nullable=False)
    detail=Column(String(100),nullable=False)
    amount =Column(Integer,nullable=False)
    formatted_datetime = column_property(func.date_format(dates,"%d-%m-%Y"))

    

class User(base):
    __tablename__='users'
    id=Column(Integer,primary_key=True,nullable=False) 
    username=Column(String(100),nullable=False,unique=True)
    password=Column(String(400),nullable=False)

class Client(base):
    __tablename__='client'
    id=Column(Integer,primary_key=True,nullable=False) 
    name=Column(String(100),nullable=False,unique=False)
    is_deleted=Column(String,nullable=False,server_default='0')
    user_id=Column(Integer,nullable=False)


class Income_pydantic(BaseModel):
    
    dates:date
    type_val:int
    detail:str 
    amount:int
    clinet_id:int
    @validator("dates", pre=True)
    def prase_formatted_datetime(cls, value):
        return datetime.strptime(
            value,
             "%d-%m-%Y"
        )
    

    class Config:
        orm_mode=True


class Token(BaseModel):
    access_token:str
    token_type:str

class TokenData(BaseModel):
    id:Optional[str] = None

class UserCreate(BaseModel):
    username:str
    password:str

class UserLogin(BaseModel):
    username:str
    password:str

class UserResponce(BaseModel):
    id:int
    username:str
    class Config:
        orm_mode=True

class dates(BaseModel):
    date_from:date
    date_to:date
    client_id:Optional[int]= None
    @validator("date_from","date_to", pre=True)
    def prase_formatted_datetime(cls, value):
        return datetime.strptime(
            
            value,
             "%d-%m-%Y"
        )

class response(BaseModel):
    id:int
    formatted_datetime:str
    type_val:int
    detail:str
    amount:int

   
    class Config:
        orm_mode=True


class clientin(BaseModel):
    name:str
   
class responseclient(BaseModel):
    id:int
    name:Optional[str]= None
   
    class Config:
        orm_mode=True


class clientID(BaseModel):
    id:int 
    class Config:
        orm_mode=True





SECRET_KEY="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

def create_access_token(data:dict):
   to_encode= data.copy()
   expire=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
   to_encode.update({'exp':expire})

   encoded_jwt= jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM) #(datalode, secret key, algorithm)
   return encoded_jwt


def verify_access_token(token:str,credentials_exceptions):
    try:
        payload=jwt.decode(token, SECRET_KEY,algorithms=[ALGORITHM])
        id:str=payload.get("user_id")

        if  id is None:
           raise credentials_exceptions
        token_data=TokenData(id=id)

    except JWTError:  
        raise credentials_exceptions
    
    return token_data
    
def get_current_user(token:str = Depends(oauth2_scheme), db:Session=Depends(get_db)):
    credentials_exceptions=HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Could not validate credentials",headers={"WWW-Authrnticate":"Bearer"})   
    
    token= verify_access_token(token,credentials_exceptions)
    user=db.query(User).filter(User.id==token.id).first()

    return user





def hash(password:str):
    
    return pbkdf2_sha256.hash(password)


def verify(plain_pass,harsh_pass):#fun gives the value of true or false
    print(plain_pass)
    print(harsh_pass)
    
    x =pbkdf2_sha256.verify(plain_pass, harsh_pass)
    
   
    return x






base.metadata.create_all(bind=engine)
app=FastAPI()
handler=Mangum(app)
# origions=["*"] 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],#domains which 
    allow_credentials=True,
    allow_methods=["*"],# allow specific mehods(get,update)
    allow_headers=["*"],#allwo which headers
)

@app.get('/')
def home():
   return{
      "message":"we are in home baby"
   }

# 
@app.post("/get",response_model=List[response])
def get_posts( d:dates,db: Session=Depends(get_db),current_user:int =Depends(get_current_user)):
    dd=d.dict()
   
    dd['date_from'] = dd['date_from'].strftime("%Y-%m-%d")
    dd['date_to'] = dd['date_to'].strftime("%Y-%m-%d")
    n=dd["client_id"]
    if n==0:
            postes=db.query(Income).filter(Income.user_id==current_user.id,Income.dates >= dd['date_from'] ,Income.dates <= dd['date_to'],Income.is_deleted=='f').order_by(Income.dates.asc(),Income.type_val.asc()).all()
          

    else:
       postes=db.query(Income).filter(Income.user_id==current_user.id,Income.dates >= dd['date_from'] ,Income.dates <= dd['date_to'],Income.is_deleted=='f',Income.clinet_id==dd["client_id"]).order_by(Income.dates.asc(),Income.type_val.asc()).all()
    return postes


@app.get("/latest")
def get_posts( db: Session=Depends(get_db),current_user:int =Depends(get_current_user)):
    user = db.query(User).filter(User.id == current_user.id).first()
    query = db.query(Income.amount).filter(Income.is_deleted=='f',Income.user_id==current_user.id,Income.type_val==1).all()
    query_exp=db.query(Income.amount).filter(Income.is_deleted=='f',Income.user_id==current_user.id,Income.type_val==2).all()
    query_pay=db.query(Income.amount).filter(Income.is_deleted=='f',Income.user_id==current_user.id,Income.type_val==3).all()
    a=0
    b=0
    c=0
    for i in query:
       a=a+i[0]
    
    for i in query_exp:
       b=b+i[0]

    for i in query_pay:
       c=c+i[0]
    profit=a-(b+c)  
    
    return  {"profit":profit,"usernaem":user.username}


@app.post("/posts",status_code=status.HTTP_201_CREATED)
def create_post(income:Income_pydantic,db: Session=Depends(get_db),current_user:int =Depends(get_current_user)):
    
    incomes=income.dict()
    
    incomes['dates'] = incomes['dates'].strftime("%Y-%m-%d")
    if incomes["detail"]=='':
       raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="no detail given")
    incomes["user_id"]=current_user.id
    new_post=Income(**incomes)
    db.add(new_post)
    db.commit()
    # db.refresh(new_post)
    
    return ("hi")


@app.post("/postsclient",status_code=status.HTTP_201_CREATED)
def create_post(name:clientin,db: Session=Depends(get_db),current_user:int =Depends(get_current_user)):
    incomes=name.dict()
    incomes["user_id"]=current_user.id
    new_post=Client(**incomes)
    db.add(new_post)
    db.commit()
    
    return ("hi")


@app.get("/getclient",response_model=List[responseclient])
def get_posts( db: Session=Depends(get_db),current_user:int =Depends(get_current_user)):
    id_user=current_user.id
    postes=db.query(Client).filter(Client.is_deleted=='f',Client.user_id==id_user).all()
    return postes

@app.post("/getclientone",response_model=List[clientID])
def get_posts(b:clientin,db: Session=Depends(get_db),current_user:int =Depends(get_current_user)):
    id_user=current_user.id
    bb=b.dict()
    postes=db.query(Client).filter(Client.is_deleted=='f',Client.user_id==id_user,Client.name.match(bb["name"])).all()
    return postes




@app.put("/delete/{id}")
def delete_post(id:int,db: Session = Depends(get_db),current_user:int =Depends(get_current_user)): #id is integer
   
    id_user=current_user.id
    post= db.query(Income).filter(Income.id==id,Income.user_id==id_user).first()
    print(post)
    post.is_deleted='t'
    
 
    db.commit()
    return ("Post deleted")



@app.put("/deleteclient/{id}")
def delete_post(id:int,db: Session = Depends(get_db),current_user:int =Depends(get_current_user)): #id is integer
    
    id_user=current_user.id
    post= db.query(Client).filter(Client.id==id,Client.user_id==id_user).first()
    post.is_deleted='t'
    
    db.commit()
    db.commit()
    return ("Post deleted")


@app.post("/user",status_code=status.HTTP_201_CREATED, response_model=UserResponce)
def create_user(new_user:UserCreate,db: Session = Depends(get_db)):
   #has the password- user.passowrd
   hashed_password=hash(new_user.password)
   print(hashed_password)
   new_user.password= hashed_password
   
   user=User(**new_user.dict())
   print(user)
   db.add(user)
   db.commit()
   db.refresh(user)
   return user





@app.post('/login')
def login( user_credentials:UserLogin, db:Session = Depends(get_db)):
 user = db.query(User).filter(User.username == user_credentials.username).first()
 username = db.query(User.username).filter(User.username == user_credentials.username).first()
 if not user:
  raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail=f"invalid credentials")
 
 if not verify( user_credentials.password,user.password): #if it is true, returns token,,,,if not it raises an exception
  raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid credentials")

 access_token=create_access_token(data={"user_id": user.id})
 print(access_token)
 return{"access_token": access_token, "token_type":"bearer","user_name":user.username}

