#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 30 18:07:24 2018

@author: jai
"""

import base64
import datetime
import json
import os
import sys
import time
import yaml

from functools import wraps
from passlib.hash import pbkdf2_sha256

import oursql

from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import Response


# returns the webapp config for runtime configuration
# creates a new one with working generated keys if not found
def get_config():
    if not os.path.isfile('/Users/Rehan/Desktop/posproject/robant/data/config.yaml'):
        with open('/Users/Rehan/Desktop/posproject/robant/data/config.yaml', 'w+') as f:
            yaml.dump({'app': {'SECRET_KEY': base64.b64encode(os.urandom(30)),
                               'debug': True,
                               'port': 5000},
                        'mysql': {'host': 'localhost',
                                  'db': 'robant',
                                  'user': 'root',
                                  'passwd': '',
                                  'port': 3306},
                        'tax_rates': {'WA': '1.07', 'DE': '1.01', 'DC': '1.08', 'WI': '1.02', 'WV': '1.05', 'HI': '1.07', 'FL': '1.10', 'WY': '1.07', 'NH': '1.03', 'NJ': '1.03', 'NM': '1.09', 'TX': '1.08', 'LA': '1.02', 'NC': '1.03', 'ND': '1.02', 'NE': '1.03', 'TN': '1.05', 'NY': '1.09', 'PA': '1.02', 'CA': '1.08', 'NV': '1.05', 'VA': '1.03', 'CO': '1.07', 'AK': '1.09', 'AL': '1.08', 'AR': '1.07', 'VT': '1.01', 'IL': '1.04', 'GA': '1.04', 'IN': '1.05', 'IA': '1.01', 'OK': '1.09', 'AZ': '1.07', 'ID': '1.10', 'CT': '1.09', 'ME': '1.10', 'MD': '1.06', 'MA': '1.06', 'OH': '1.06', 'UT': '1.08', 'MO': '1.08', 'MN': '1.04', 'MI': '1.03', 'RI': '1.05', 'KS': '1.07', 'MT': '1.07', 'MS': '1.09', 'SC': '1.05', 'KY': '1.05', 'OR': '1.03', 'SD': '1.02'}}, f, default_flow_style=False)

    with open('data/config.yaml') as f:
        config = yaml.load(f)
        return config


# forces user to have a logged-in session to view the decorated page
# redirects to the login page on failure
def require_login(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not session.get('username'):
            return redirect('/?next=%s' % (request.path,), 302)

        return func(*args, **kwargs)

    return decorated_view


# create webapp and configure it for sessions/cookie use
app = Flask(__name__)
config = get_config()
app.config.update(config.get('app', {}))


# orders page
@require_login
@app.route('/orders')
def orders_page():
    # fetch all orders
    with oursql.connect(**config.get('mysql')) as c:
        c.execute("SELECT orders.id, orders.userid, users.username, orders.timestamp, orders.billing_name, orders.billing_email, orders.billing_address, orders.billing_city, orders.billing_state, orders.billing_zip, orders.payment_name, orders.payment_card, orders.payment_exp, orders.payment_cvv, orders.shipping_same, orders.order, orders.total FROM orders LEFT JOIN users ON orders.userid = users.id ORDER BY id ASC")
        orders = c.fetchall()
        orders = [{'id': o[0],
                   'username': o[2],
                   'timestamp': datetime.datetime.fromtimestamp(int(o[3])).strftime('%Y-%m-%d %H:%M:%S'),
                   'billing': "%s (%s)<br>%s<br>%s, %s %s" % (o[4], o[5], o[6], o[7], o[8], o[9],),
                   'payment': "%s<br>%s<br>%s %s" % (o[10], o[11], o[12], o[13],),
                   'same_shipping': o[14],
                   'order': '<br>'.join(['%sx %s' % (x[1], x[0],) for x in json.loads(o[15])]),
                   'total': o[16]} for o in orders]
        return render_template('orders.html', orders=orders)

    return render_template('orders.html')


# checkout page
@require_login
@app.route('/checkout')
def checkout_page():
    return render_template('checkout.html')


# users page
@require_login
@app.route('/users')
def users_page():
    # fetch all users
    with oursql.connect(**config.get('mysql')) as c:
        c.execute("SELECT id, username, firstname, lastname, company FROM users ORDER BY id ASC")
        return render_template('users.html', users=c.fetchall())


# checkout page - form submission target
@require_login
@app.route('/checkout', methods=['POST'])
def checkout_page_post():
    # fetch all users
    with oursql.connect(**config.get('mysql')) as c:
        c.execute("INSERT INTO orders VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (session.get('id'),
                                                                                                    int(time.time()),
                                                                                                    request.form.get('fullname'),
                                                                                                    request.form.get('email'),
                                                                                                    request.form.get('address'),
                                                                                                    request.form.get('city'),
                                                                                                    request.form.get('state'),
                                                                                                    request.form.get('zip'),
                                                                                                    request.form.get('cardname'),
                                                                                                    request.form.get('cardnum'),
                                                                                                    "%s/%s" % (request.form.get('exp_mm'), request.form.get('exp_yy'),),
                                                                                                    request.form.get('cvv'),
                                                                                                    1 if request.form.get('same_addr')=='on' else 0,
                                                                                                    request.form.get('order'),
                                                                                                    request.form.get('total_input'),))

    return render_template('checkout_success.html')


# register page
@app.route('/register')
def register_page():
    return render_template('registerusername.html')


# register - form submission target
@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    firstname = request.form.get('firstname')
    lastname = request.form.get('lastname')
    company = request.form.get('company')

    # constraints on usernames and other inputs would go here

    # check if username is taken
    with oursql.connect(**config.get('mysql')) as c:
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        r = c.fetchall()
        if r:
            return render_template('registerusername.html', error="Username is taken", username=username, lastname=lastname, firstname=firstname, company=company)

    # passed checks - hash password and insert user into database
    pw_crypt = pbkdf2_sha256.using(rounds=8000, salt_size=10).hash(password)
    with oursql.connect(**config.get('mysql')) as c:
        c.execute("INSERT INTO users VALUES (NULL, ?, ?, ?, ?, ?)", (username, pw_crypt, firstname, lastname, company,))

    return redirect('/')


# login - form submission target
@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    # check database for user
    with oursql.connect(**config.get('mysql')) as c:
        c.execute("SELECT id, username, password, firstname, lastname, company FROM users WHERE username = ?", (username,))
        r = c.fetchall()
        if r:
            # user found, check password
            r = r[0]
            if pbkdf2_sha256.verify(password, r[2]):
                # login successful
                session['id'] = r[0]
                session['username'] = r[1]
                session['firstname'] = r[3]
                session['lastname'] = r[4]
                session['company'] = r[5]
                return redirect('/')

    # no user found OR user found & password verification failed
    return render_template('mainlogin.html', error="Wrong username or password", username=username)


# logout
@require_login
@app.route('/logout')
def logout_page():
    for key in session.keys():
        del session[key]
    session.clear()
    return redirect('/')


# serve tax rates for js calculation on checkout page
@app.route('/tax_rates')
def tax_rates_page():
    return Response(content_type='application/json',
                    response=json.dumps(config.get('tax_rates')))


# main page
@app.route('/')
def home():
    # if they're logged in, send them to the checkout form
    if session.get('username'):
        return redirect('/checkout')

    # or else show them the login
    return render_template('mainlogin.html')


# run the webapp when the python file is executed directly
if __name__ == "__main__":
    if any(['debug' in x for x in sys.argv]):
        app.run(host='0.0.0.0',
                port=config.get('app', {}).get('port', 8000),
                use_reloader=True,
                debug=True)
    else:
        from waitress import serve
        serve(app,
              host='0.0.0.0',
              port=config.get('app', {}).get('port', 8000))