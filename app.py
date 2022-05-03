import datetime
import json
import os
from collections import defaultdict
from uuid import uuid4

import requests
import stripe
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request)
from flask_cors import CORS, cross_origin
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
from flask_jwt_extended.internal_utils import get_jwt_manager
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from config import DevelopmentConfig, ProductionConfig
from logic import format_db_row_to_transaction

#CONFIG INICIAIS
app = Flask(__name__)
app.config.from_object(ProductionConfig)
jwt = JWTManager(app)
db = SQLAlchemy(app)
db.init_app(app)
mail=Mail(app)
cors = CORS(app)
stripe.api_key = app.config['STRIPE_SECRET_KEY']

def get_uuid():
    return uuid4().hex

#Importações de preços e nomes para formatação no frontend
LIVE_PRICE_URL = os.environ["LIVE_PRICE"]
MAP_URL = os.environ["MAP"]
USD_URL = os.environ["USD"]

###INFOS PARA O CAMPO DE SELEÇÃO DE CRIPTOMOEDAS NO FRONTEND
json_data = requests.get(MAP_URL).json()
data = json_data


symbol_to_coin_id_map = dict()
for currency in data:
        id_c = currency['id']
        name_c = currency['name']
        symbol_to_coin_id_map[name_c] = id_c


name_to_symbol_map = dict()
for currency in data:
        name_c = currency['name']
        symbol_c=currency['symbol']
        image_c=currency['image']
        name_to_symbol_map[name_c] = symbol_c

name_to_image_map = dict()
for currency in data:
        name_c = currency['name']
        image_c=currency['image']
        name_to_image_map[name_c] = image_c

###BASE DE DADOS
class Users(db.Model):
    id = db.Column(db.String(32), primary_key=True, unique=True, default=get_uuid)
    name = db.Column(db.Text, nullable=False)
    surname = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(345), unique=True)
    password = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default= datetime.datetime.now())
    role = db.Column(db.String(100), nullable=True)
    premium = db.Column(db.Integer, nullable=True)
    stripeUser= db.Column(db.String(150), nullable=True)

    ##DEF PARA GERAÇÃO DE EMAIL EM CASO DE RECUPERAÇÃO DE SENHA
    def get_token(user):
        access_token = create_access_token(identity=user.id)
        return access_token

    @staticmethod
    def decode_token(token, csrf_value=None, allow_expired=True):
        jwt_manager = get_jwt_manager()
        token_id = jwt_manager._decode_jwt_from_config(token, csrf_value, allow_expired)
        return token_id


class userstripe(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(32), db.ForeignKey(Users.id))
    stripeCustomerId = db.Column(db.String(255))
    stripeSubscriptionId = db.Column(db.String(255))
    paymentStatus = db.Column(db.String(100))
    email = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default= datetime.datetime.now())

#####FUNÇÃO PARA EMAIL DE RESET DE SENHA


###############
def send_mail(user):
    token=user.get_token()
    msg = Message('Pedido de Reset de Senha', recipients=[user.email],sender='noreply@ghostportfolio.com')
    msg.html = render_template('email.html', token=token)
    mail.send(msg)

######ROTAS###################
##############################

######ABERTAS
@app.route("/")
def root():
    return jsonify ({"Hello":"There"})

###CRIAÇÃO DE USUÁRIO
@app.route("/sign-up", methods=['POST'])
@cross_origin()
def sign_up():
        username =  request.json["username"]
        usersurname =  request.json["usersurname"]
        email1 =  request.json["email1"]
        email2 =  request.json["email2"]
        password1 =  request.json["password1"]
        password2 =  request.json["password2"]


        email_exists = Users.query.filter_by(email=email1).first()
        if email1 != email2:
            return jsonify({ "Erro": "Emails não coincidem"}), 409
        elif email_exists:
            return jsonify({ "Erro": "Email já está em uso!"}), 409
        elif password1 != password2:
            return jsonify({ "Erro": "As duas senhas precisam ser iguais!"}), 409
        elif len(email1) < 5:
            return jsonify({ "Erro": "Email inválido!"}), 409
        elif len(password1) < 8:
            return jsonify({ "Erro": "A senha precisa ter no mínimo 8 caracteres!"}), 409
        else:
            customer = stripe.Customer.create(email=request.json["email1"])
            hashed_password = generate_password_hash(password1, method='sha256')
            new_user = Users(name=username, surname=usersurname, email=email1, password=hashed_password, role="newUser", premium=0, stripeUser=customer.id)
            db.session.add(new_user)
            db.session.commit()
        
        return jsonify({
            "id": new_user.id,
            "nome": new_user.name,
            "sobrenome": new_user.surname,
            "email": new_user.email,
            "password": new_user.password,
            "data_criacao": new_user.created_at.strftime("%d/%m/%Y"),
            "role": new_user.role,
            "stripe": new_user.stripeUser
        })



@app.route("/login", methods=["POST"])
@cross_origin()
def login():
    email =  request.json["email"]
    password =  request.json["password"]

    user = Users.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "Email não existe em nossa base de dados"}), 401
    elif not check_password_hash(user.password, password):
        return jsonify({"error": "Senha errada"}), 401
    else:
        username = user.id
        access_token = create_access_token(identity=username)
    
    premium_check = int(user.premium)
    stripeId = user.stripeUser

    customer = userstripe.query.filter_by(stripeCustomerId=stripeId).first()

    #check for ending of free trial
    usercreation = user.created_at
    date_now = datetime.datetime.now()
    check_user_creation = int((date_now - usercreation).days)

    subscription = ""
    product = ""
    isActive= ""

    if check_user_creation > 15 and premium_check == 0 :
        user.role = "expired"
        user.premium = 0
        db.session.commit()

    # if record exists, add the subscription info
    if customer and premium_check == 1:
        subscription = stripe.Subscription.retrieve(customer.stripeSubscriptionId)
        product = stripe.Product.retrieve(subscription.plan.product)
        isActive = subscription['items']['data'][0]['plan']['active']
    # if cancel subscription
    elif isActive == 'false':
        user.role = "expired"
        db.session.commit()
    # else return empty


    return jsonify({
        
        "user":{
            "id": user.id,
            "email": user.email,
            "user_status": user.role,
            "check": premium_check,
            "isActive": isActive
        }, 
        "token":access_token,
        "context": {
            "subscription": subscription,
            "product": product
        },
        }     
    )

###EMAIL DE CONTATO
@app.route("/contact-mail", methods=['POST'])
def contact_mail():
        email = request.json['email']
        name = request.json['name']
        subject = request.json['subject']
        message = request.json['message']
        personal_mail= app.config['PERSONAL_MAIL']

        msg = Message(subject, recipients=[personal_mail],sender='contato@ghostportfolio.com')
        msg.body =f'''
        dados do contato
        nome: {name}
        email: {email}
        mensagem: {message}
        
        '''

        mail.send(msg)

        return jsonify({"success": "Email enviado"}),200


#####RESET DE SENHA -ENVIO
@app.route("/reset_password", methods=['GET', 'POST'])
@cross_origin()
def reset_request():
    email =  request.json["email"]

    user = Users.query.filter_by(email=email).first()

    if not user:
        return jsonify({"erro": "usuário não existe"}), 401

    send_mail(user)
    return jsonify({"success": "Email enviado"}),200

#####RESET DE SENHA - REDIRECIONAMENTO DO EMAIL
@app.route("/redirect_route/<token>", methods=['GET', 'POST'])
@cross_origin()
def redirect_route(token):
    host = app.config['FRONTEND_URL']

    url_redirect=f"{host}/reset/ghost#access_token={token}"

    return redirect(url_redirect)



#####RESET DE SENHA - REQUEST VINDO DO FRONTEND
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
@cross_origin()
def reset_token(token):
    userdecode = Users.decode_token(token)['sub']
    
    user = Users.query.filter_by(id=userdecode).first()

    if token is None:
        return flash("Seu período para reset expirou, faça o pedido novamente", 'warning')
    if userdecode is None:
        return flash("Este usuário não existe em nossa base de dados", 'warning')

    newpassword =  request.json["newpassword"]
    check_newpassword = request.json["check_newpassword"]

    
    if newpassword != check_newpassword:
        return jsonify({ "Erro": "As duas senhas precisam ser iguais!"}), 409
    elif len(newpassword) < 8:
        return jsonify({ "Erro": "A senha precisa ter no mínimo 8 caracteres!"}), 409
    else:
        hashed_password = generate_password_hash(newpassword, method='sha256')
        user.password=hashed_password
        db.session.commit()
    
    return jsonify({
            "Senha": "Alterada"
        })

##########################################################################################

######PROTEGIDAS

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

###Editar informações DE USUÁRIO
@app.route("/edit_info", methods=['POST'])
@jwt_required()
@cross_origin()
def user_edit():
        user_id = get_jwt_identity()

        password =  request.json["password"]

        if len(password) < 8:
            return jsonify({ "Erro": "A senha precisa ter no mínimo 8 caracteres!"}), 409
        else:
            user = Users.query.filter_by(id=user_id).first()
            hashed_password = generate_password_hash(password, method='sha256')
            user.password = hashed_password
            db.session.commit()
        
        return jsonify({
            "id": user.id,
            "nome": user.name,
            "sobrenome": user.surname,
            "email": user.email,
            "password": user.password,
            "data_criacao": user.created_at.strftime("%d/%m/%Y"),
            "role": user.role
        })

@app.route("/transactions", methods=["POST"])
@jwt_required()
@cross_origin()
def new_transaction():
    user_id = get_jwt_identity()

    name = request.json["name"]
    type = request.json["type"]
    amount = request.json["amount"]
    price_purchased_at = request.json["price_purchased_at"]
    no_of_coins = float(request.json["no_of_coins"])

    if type == '1':
        insert_statement = f"INSERT INTO transaction (name, type, amount, price_purchased_at, no_of_coins, user_id) VALUES ('{name}', {type}, {amount}, {price_purchased_at}, {no_of_coins}, '{user_id}')"
        db.session.execute(insert_statement)
        db.session.commit()

        return jsonify(request.json)

    if type == '2':
        weighted_statment= f"SELECT name, type, sum(no_of_coins * price_purchased_at) / sum(no_of_coins) as price_average FROM transaction WHERE name='{name}' AND type=1 AND user_id='{user_id}' GROUP BY name"
        
        rows = db.session.execute(weighted_statment)
        for row in rows:
                    transaction_amount = row[2]

                    price_purchased_at = transaction_amount
        

        insert_sell_statement = f"INSERT INTO transaction (name, type, amount, price_purchased_at, no_of_coins, user_id) VALUES ('{name}', {type}, {amount}, {price_purchased_at}, {no_of_coins}, '{user_id}')"
        db.session.execute(insert_sell_statement)
        
        db.session.commit()

        return jsonify(request.json)

@app.route("/transactions")
@jwt_required()
@cross_origin()
def get_transactions():
    
    user_id = get_jwt_identity()

    select_byId = f"SELECT * FROM transaction WHERE user_id = '{user_id}'"     
    rows = db.session.execute(select_byId)

    return jsonify(
        [
            format_db_row_to_transaction(row)
            for row in rows
        ]
    )

@app.route("/get_rollups_by_coin")
@jwt_required()
@cross_origin()
def get_rollups_by_coin_byid():
    
    user_id = get_jwt_identity()

    portfolio = defaultdict(
        lambda: {
            "coins": 0,
            "total_cost": 0,
            "total_equity": 0,
            "live_price": 0,
            "variation24h":0,
            "symbol":"",
            "image":"",
            "average_p":0,
            "p_l":0,
            "p_l_p":0,
            "bitcoin_lp":0,
            "usd_cot":0,
            "brl_conv_total":0,
        }
    )

    select_statement = f"SELECT name, type, SUM(amount)/100 AS total_amount, SUM(no_of_coins) AS total_coins, SUM(no_of_coins * price_purchased_at) AS sell_cost FROM transaction where user_id='{user_id}' GROUP BY name, type"
    rows = db.session.execute(select_statement)
    for row in rows:
            coin = row[0]
            transaction_type = row[1]
            transaction_amount = row[2]
            transaction_coins = row[3]
            transaction_cost = row[4]

            #compra
            if transaction_type == 1:
                portfolio[coin]['total_cost'] += transaction_amount
                portfolio[coin]['coins'] += transaction_coins

            #venda
            else:                
                portfolio[coin]['total_cost'] -= transaction_cost
                portfolio[coin]['coins'] -= transaction_coins


    symbol_to_coin_id_map
    name_to_symbol_map

    rollup_response=[]

    for name in portfolio:
            response = requests.get(
                f"{LIVE_PRICE_URL}?ids={symbol_to_coin_id_map[name]}&vs_currencies=usd&include_24hr_change=true"
            ).json()
            response2 = requests.get(
                f"{LIVE_PRICE_URL}?ids=bitcoin&vs_currencies=usd&include_24hr_change=true"
            ).json()
            response3 = requests.get(USD_URL).json()
            live_price = response[symbol_to_coin_id_map[name]]['usd']
            variation24h = response[symbol_to_coin_id_map[name]]['usd_24h_change']
            symbol = name_to_symbol_map[name]
            image = name_to_image_map[name]
            bitcoin_lp = response2['bitcoin']['usd']
            usd_cot = response3["USDBRL"]["bid"]
            

            portfolio[name]['usd_cot'] = usd_cot
            portfolio[name]['bitcoin_lp'] = bitcoin_lp 
            portfolio[name]['image'] = image       
            portfolio[name]['symbol'] = symbol
            portfolio[name]['name'] = name
            portfolio[name]['live_price'] = live_price
            portfolio[name]['total_equity'] = float(
                float(portfolio[name]['coins']) * live_price
            )
            portfolio[name]['variation24h'] = variation24h
            if portfolio[name]['total_cost'] == 0 or portfolio[name]['coins'] == 0:
                portfolio[name]['average_p'] = 0
            else:
                portfolio[name]['average_p'] = float(portfolio[name]['total_cost'])/float(portfolio[name]['coins'])
            portfolio[name]['p_l'] = float(
                float(portfolio[name]['coins']) * live_price - portfolio[name]['total_cost'])
            if portfolio[name]['p_l'] == 0 or portfolio[name]['total_cost'] == 0:
                portfolio[name]['p_l_p'] = 0
            else:
                portfolio[name]['p_l_p'] = float(portfolio[name]['p_l'] / portfolio[name]['total_cost']) * 100
            brl_conv_total = float(usd_cot) * portfolio[name]['total_equity']
            

            

            rollup_response.append({
                "name": name,
                "symbol":symbol.upper(),
                "image":image,
                "live_price": portfolio[name]['live_price'],
                "total_equity": portfolio[name]['total_equity'],
                "coins": portfolio[name]['coins'],
                "total_cost": portfolio[name]['total_cost'],
                "variation24h": portfolio[name]['variation24h'],
                "average_p": portfolio[name]['average_p'],
                "p_l": portfolio[name]['p_l'],
                "p_l_p": portfolio[name]['p_l_p'],
                "bitcoin_lp": bitcoin_lp,
                "usd_cot": usd_cot,
                "brl_conv_total": brl_conv_total,
                
            })

    return jsonify(rollup_response)

@app.route("/transactions", methods=["DELETE"])
@jwt_required()
@cross_origin()
def delete_transaction_byid():
    user_id = get_jwt_identity()

    name = request.json["name"]

    delete_statement = f"DELETE FROM transaction WHERE user_id='{user_id}' AND name = '{name}'"
    db.session.execute(delete_statement)
    db.session.commit()

    return jsonify({"excluído":"Sucesso"})


@app.route('/webhook', methods=['POST'])
def webhook():
    
    if request.content_length > 1024 * 1024:
        print('Request too big')
        abort(400)
    event = None
    payload = request.data
    sig_header = request.headers['STRIPE_SIGNATURE']
    endpoint_secret = app.config['ENDPOINT_SECRET']

    try:
        event = json.loads(payload)
    except:
        print('⚠️  Webhook error while parsing basic request.' + str(e))
        return jsonify(success=False)

    try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
    except stripe.error.SignatureVerificationError as e:
            print('⚠️  Webhook signature verification failed.' + str(e))
            return jsonify(success=False)
    
    if event['type'] == 'checkout.session.completed':
        session = event["data"]["object"]
        email = event['data']['object']['customer_details']['email']
        customer_id = event['data']['object']['customer']
        subscription_id = event['data']['object']['subscription']

    # Save an order in your database, marked as 'awaiting payment'
        database_mainusers = Users.query.filter_by(stripeUser=customer_id).first()
        database_stripeusers = userstripe.query.filter_by(stripeCustomerId=customer_id).first()

        database_stripeusers.stripeSubscriptionId = subscription_id
        database_stripeusers.paymentStatus = 'awaiting payment'
        database_stripeusers.email = email
        db.session.commit()
        print(session)
        create_order(session)


    elif event['type'] == 'payment_intent.succeeded':
        session = event['data']['object']
        customer_id = event['data']['object']['customer']

        database_mainusers = Users.query.filter_by(stripeUser=customer_id).first()
        database_stripeusers = userstripe.query.filter_by(stripeCustomerId=customer_id).first()


        database_mainusers.premium = 1
        database_mainusers.role = 'Premium'
        database_stripeusers.paymentStatus = 'paid'
        db.session.commit()


        # Fulfill the purchase
        fulfill_order(session)

    elif event['type'] == 'checkout.session.async_payment_failed':
        session = event['data']['object']

        # Send an email to the customer asking them to retry their order
        email_customer_about_failed_payment(session)

    if event['type'] == 'invoice.payment_succeeded':
        email = event['data']['object']['customer_email']
        customer_id = event['data']['object']['customer']
        paid = event['data']['object']['paid']

        database_stripeusers = userstripe.query.filter_by(stripeCustomerId=customer_id).first()
        database_stripeusers.paymentStatus = paid
        db.session.commit()
        
    
        print(email, customer_id)

    return "Success", 200

def fulfill_order(session):
      # TODO: fill me in
  print("Fulfilling order")

def create_order(session):
  # TODO: fill me in
  print("Creating order")

def email_customer_about_failed_payment(session):
  # TODO: fill me in
  print("Emailing customer")

def handle_checkout_session(session):
    # here you should fetch the details from the session and save the relevant information
    # to the database (e.g. associate the user with their subscription)
    print("Subscription was successful.")
     

@app.route("/create-checkout-session", methods=['POST'])
@jwt_required()
@cross_origin()
def create_checkout_session():
    user_id = get_jwt_identity()
    domain_url = app.config['FRONTEND_URL']

    user = Users.query.filter_by(id=user_id).first()

    client_reference_id=user.stripeUser

    try:
        checkout_session = stripe.checkout.Session.create(
            # you should get the user id here and pass it along as 'client_reference_id'
            #
            # this will allow you to associate the Stripe session with
            # the user saved in your database
            #
            # example: client_reference_id=user.id,
            customer=client_reference_id,
            client_reference_id=client_reference_id,
            success_url=domain_url + "/success/?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=domain_url + "/cancel/",
            payment_method_types=["card"],
            mode="subscription",
            line_items=[
                {
                    "price": app.config['STRIPE_PRICE_ID'],
                    "quantity": 1,
                }
            ]
            
        )
        new_user = userstripe(stripeCustomerId=checkout_session.client_reference_id, user_id=user.id)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"sessionId": checkout_session["id"]})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route("/create-checkout-session-anualplan", methods=['POST'])
@jwt_required()
@cross_origin()
def create_checkout_session_anualplan():
    user_id = get_jwt_identity()
    domain_url = app.config['FRONTEND_URL']

    user = Users.query.filter_by(id=user_id).first()

    client_reference_id=user.stripeUser

    try:
        checkout_session = stripe.checkout.Session.create(
            # you should get the user id here and pass it along as 'client_reference_id'
            #
            # this will allow you to associate the Stripe session with
            # the user saved in your database
            #
            # example: client_reference_id=user.id,
            customer=client_reference_id,
            client_reference_id=client_reference_id,
            success_url=domain_url + "/success/?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=domain_url + "/cancel/",
            payment_method_types=["card"],
            mode="subscription",
            line_items=[
                {
                    "price": app.config['STRIPE_PRICE_ID_ANUALPLAN'],
                    "quantity": 1,
                }
            ]
            
        )
        new_user = userstripe(stripeCustomerId=checkout_session.client_reference_id, user_id=user.id)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"sessionId": checkout_session["id"]})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route('/create-customer-portal-session', methods=['POST'])
@jwt_required()
@cross_origin()
def customer_portal():

  # Authenticate your user.
  user_id = get_jwt_identity()
  user = Users.query.filter_by(id=user_id).first()

  customer_id = user.stripeUser

  session = stripe.billing_portal.Session.create(
    customer=customer_id,
    return_url=app.config['FRONTEND_URL'],
  )
  return jsonify(session.url)


#######FINAL
#######################################
if __name__ == "__main__":
    app.run()
