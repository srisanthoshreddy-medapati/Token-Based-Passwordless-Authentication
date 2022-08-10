from fastapi import FastAPI, status, Header
from fastapi.middleware.cors import CORSMiddleware
import random
import uvicorn
import os
from dotenv import load_dotenv
import requests
import re
import secrets
import databases
import sqlalchemy
from pydantic import BaseModel
import urllib
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime
from dateutil.relativedelta import relativedelta
import urllib3


app = FastAPI()

load_dotenv()

if __name__ == '__main__':
    uvicorn.run('main:app', reload=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

host_server = os.getenv('host_server')
db_server_port = urllib.parse.quote_plus(str(os.getenv('db_server_port')))
database_name = os.getenv('database_name')
db_username = urllib.parse.quote_plus(str(os.getenv('db_username')))
db_password = urllib.parse.quote_plus(str(os.getenv('db_password')))
ssl_mode = urllib.parse.quote_plus(str(os.getenv('ssl_mode')))
DATABASE_URL = 'postgresql://{}:{}@{}:{}/{}?sslmode={}'.format(db_username,db_password, host_server, db_server_port, database_name, ssl_mode)
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("user_id", sqlalchemy.Integer,sqlalchemy.Sequence('user_id_seq'),primary_key=True),
    sqlalchemy.Column("email_id", sqlalchemy.String,unique=True),
    sqlalchemy.Column("name",sqlalchemy.String)
    )

otps = sqlalchemy.Table(
    "otps",
    metadata,
    sqlalchemy.Column("email_id", sqlalchemy.String,primary_key=True),
    sqlalchemy.Column("otp", sqlalchemy.Integer),
    sqlalchemy.Column("createdat", sqlalchemy.TIMESTAMP,nullable=False)
)

authorizedtokens = sqlalchemy.Table(
    "authorizedtokens",
    metadata,
    sqlalchemy.Column("user_id",sqlalchemy.Integer),
    sqlalchemy.Column("auth_token",sqlalchemy.String),
    sqlalchemy.Column("createdat", sqlalchemy.TIMESTAMP,nullable=False)
)

engine = sqlalchemy.create_engine(
    DATABASE_URL, pool_size=3, max_overflow=0
)
metadata.create_all(engine)
    
class LoginRequest(BaseModel):
    email_id: str
    otp: Union[int,None] = None


@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.get("/")
def root():
    return {"message": "Token based passwordless authentication"}
    
@app.post("/signin")
async def read_emai(request: LoginRequest):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(re.fullmatch(regex, request.email_id)):
        url = "https://api.sendinblue.com/v3/smtp/email"
        otp=random.randint(100000,999999)
        query1= otps.select().filter(otps.c.email_id ==request.email_id)
        if(await database.fetch_one(query1)):
            query2 = otps.update().where(otps.c.email_id==request.email_id).values(otp=otp,createdat=datetime.now())
        else:
            query2 = otps.insert().values(email_id=request.email_id, otp=otp, createdat=datetime.now())
        await database.execute(query2)
        data={
   	"from":{
      "email":"me@srisanthoshreddy.xyz"
   },
   "personalizations":[
      {
         "to":[
            {
               "email":request.email_id
            }
         ],
         "dynamic_template_data":{
            "code":otp
          }
      }
   ],
   "template_id" : os.getenv('confirm_template_id')
}
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.client.mail.send.post(request_body=data)
        print(response.status_code)
        print(response.body)
        print(response.headers)
        return {"Status": "OK"}
    else:
        return {"Status":"Invalid Email"}

@app.get("/check")
async def check_user(token: Union[str, None] = Header(default=None)):
    query = authorizedtokens.select().filter(authorizedtokens.c.token == token , authorizedtokens.c.created > (datetime.now()-relativedelta(days=120)))
    if(await database.fetch_one(query)):
        return {"Status":"Login successful"}  
    else:
        query2 = authorizedtokens.delete().filter(authorizedtokens.c.token == token)
        await database.execute(query2)
        return {"Status":"Login expired"}
    
    
@app.post("/confirm")
async def confirm_email(request: LoginRequest):
    query = otps.select().filter(otps.c.email_id == request.email_id, otps.c.otp == request.otp, otps.c.createdat > (datetime.now()-relativedelta(seconds=180)))
    if(await database.fetch_one(query)):
        token=generate_key()
        query2 = users.select().filter(users.c.email_id == request.email_id)
        if(await database.fetch_one(query2)):
            print("old user")
        else :
            await database.execute(users.insert().values(email_id=request.email_id))
            print("New user created")
        query3= users.select().where(users.c.email_id==request.email_id)
        user=await database.fetch_one(query3)
        await database.execute(authorizedtokens.insert().values(user_id=user["user_id"], auth_token=token, createdat=datetime.now()))
        await database.execute(otps.delete().filter(otps.c.otp == request.otp))
        return {"token":token}
    else:
        return {"Status":"Invalid Code"}      


def generate_key():
    return secrets.token_hex(32)
