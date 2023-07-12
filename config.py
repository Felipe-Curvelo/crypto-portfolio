from dotenv import load_dotenv
load_dotenv()
import os

import datetime

class Config(object):

    PERSONAL_MAIL=os.environ['PERSONAL_MAIL']

    JWT_SECRET_KEY=os.environ["JWT_SECRET_KEY"]
    JWT_ACCESS_TOKEN_EXPIRES= datetime.timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = datetime.timedelta(hours=24)

    SECRET_KEY=os.environ["SECRET_KEY"]
    
    SQLALCHEMY_DATABASE_URI = os.environ["SQLALCHEMY_DATABASE_URI"]

    MAIL_SERVER = 'smtp-relay.sendinblue.com'
    MAIL_PORT = 587
    MAIL_USERNAME = os.environ["MAIL_USERNAME"]
    MAIL_PASSWORD = os.environ["MAIL_PASSWORD"]

    FRONTEND_URL = os.environ["FRONTEND_URL"]

    STRIPE_SECRET_KEY= os.environ["STRIPE_SECRET_KEY"]
    STRIPE_PUBLISHABLE_KEY= os.environ["STRIPE_PUBLISHABLE_KEY"]
    STRIPE_PRICE_ID= os.environ["STRIPE_PRICE_ID"]
    STRIPE_PRICE_ID_ANUALPLAN= os.environ["STRIPE_PRICE_ID_ANUALPLAN"]
    ENDPOINT_SECRET=os.environ["ENDPOINT_SECRET"]



class DevelopmentConfig(Config):
    JWT_COOKIE_SECURE=False
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_ECHO = True
    DEBUG=True

class ProductionConfig(Config):
    JWT_COOKIE_SECURE=True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    DEBUG=False
