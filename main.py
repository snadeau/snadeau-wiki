#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import re
import string
import hashlib
import random
import time

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
SECRET = 'vo2Hc4Ebs3rA9'

#
#Models
#

class Page(db.Model):
    content = db.TextProperty()
    pageid = db.StringProperty(required = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.EmailProperty()

#
#Signup Form Verification Functions
#
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

#
#Hashing/Verification Functions
#
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))
  
def hash_password(username, password, salt = None):
    if not salt:
        salt = make_salt()
    hashed = hashlib.sha256(username + password + salt).hexdigest()
    return str.format('{0},{1}', hashed, salt)

def check_password(username, password, hashed):
    passedhash, passedsalt = hashed.split(",")
    checkhash = hash_password(username, password, salt = passedsalt)
    newhash = checkhash.split(",")[0]
    if newhash == passedhash:
        return True
    else:
        return False

def make_cookie(userid):
    hashval = hashlib.sha256(str(userid) + SECRET).hexdigest()
    return str.format('{0}|{1}', userid, hashval)

def validate_cookie(cookie):
    userid, hashed = cookie.split("|")
    hashcheck = hashlib.sha256(str(userid) + SECRET).hexdigest()
    if hashed == hashcheck:
        return True
    else:
        return False

    
#
#Handlers
#

class Handler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render_str(self, template, **kwargs):
        template = jinja_env.get_template(template)
        return template.render(kwargs)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, **kwargs))

    

class WikiHandler(Handler):
    def get(self, pageid):
        cookie = self.request.cookies.get('user')
        if not cookie:
            cookie = '|'
        c = db.GqlQuery("SELECT * FROM Page WHERE pageid = :1", pageid)
        page = c.get()
        if page:
            self.render(template = 'wiki.html',
                        loggedin = validate_cookie(cookie),
                        pageid = pageid,
                        content = page.content)
        else:
            if validate_cookie(cookie):
                self.redirect('/_edit%s' % pageid)
            else:
                self.redirect('/login')
            

class LoginHandler(Handler):
    def get(self):
        self.render(template = 'login.html',
                    username = '',
                    loginerror = '')
    def post(self):
        errorflag = False
        username = self.request.get('username')
        password = self.request.get('password')
        loginerror = ''
        c = db.GqlQuery("SELECT * FROM User WHERE username = :1", username)
        user = c.get()
        if user:
            if check_password(username, password, user.password):
                userid = user.key().id()
                self.response.headers.add_header('Set-Cookie',
                                                 'user=%s; Path=/' % make_cookie(userid))
                self.redirect('/')
            else:
                self.render(template = 'login.html',
                            username = username,
                            loginerror = "Username and/or Password Invalid")
        else:
            self.render(template = 'login.html',
                        username = username,
                        loginerror = "Username and/or Password Invalid")
                        
                        

class SignupHandler(Handler):
    def get(self):
        self.render(template = 'signup.html',
                    username = '',
                    usererror = '',
                    duplicateerror = '',
                    passerror = '',
                    verifyerror = '',
                    email = '',
                    emailerror = '')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        errorflag = False
        usererror = ''
        passerror = ''
        verifyerror = ''
        emailerror = ''
        duplicateerror = ''
        
        if not valid_username(username):
            errorflag = True
            usererror = "Username is invalid"
        if not valid_password(password):
            errorflag = True
            passerror = "Password is invalid"
        if password != verify:
            errorflag = True
            verifyerror = "Passwords do not match"
        if email:
            if not valid_email(email):
                errorflag = True
                emailerror = "Email is invalid"

        c = db.GqlQuery("SELECT * FROM User WHERE username = :1", username)
        user = c.get()
        if user:
            errorflag = True
            duplicateerror = "User already exists"

        if errorflag:
            self.render(template = 'signup.html',
                        username = username,
                        usererror = usererror,
                        duplicateerror = duplicateerror,
                        passerror = passerror,
                        verifyerror = verifyerror,
                        email = email,
                        emailerror = emailerror)
        else:
            hashedpassword = hash_password(username, password)
            if not email:
                newuser = User(username = username,
                               password = hashedpassword)
            else:
                newuser = User(username = username,
                               password = hashedpassword,
                               email = email)
            newuser.put()
            userid = newuser.key().id()
            self.response.headers.add_header('Set-Cookie',
                                             'user=%s; Path=/' % make_cookie(userid))
            self.redirect('/')

class EditHandler(Handler):
    def get(self, pageid):
        content = ''
        c = db.GqlQuery("SELECT * FROM Page WHERE pageid = :1", pageid)
        page = c.get()
        if page:
            content = page.content
        self.render(template = 'edit.html',
                    loggedin = True,
                    content = content)

    def post(self, pageid):
        cookie = self.request.cookies.get('user')
        if cookie:
            if validate_cookie(cookie):
                inputText = self.request.get('inputText')
                c = db.GqlQuery("SELECT * FROM Page WHERE pageid = :1", pageid)
                pageexists = c.get()
                if pageexists:
                    key = pageexists.key()
                    newEntry = Page(content = inputText,
                                    pageid = pageid,
                                    key = key)
                    newEntry.put()
                else:
                    newEntry = Page(content = inputText,
                                    pageid = pageid)
                    newEntry.put()
                time.sleep(.5)
                self.redirect(pageid)
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')
                         
    
class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user=; Path=/')
        self.redirect('/')
        
app = webapp2.WSGIApplication([
    ('/logout', LogoutHandler),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/_edit' + PAGE_RE, EditHandler),
    (PAGE_RE, WikiHandler),  
], debug=True)
