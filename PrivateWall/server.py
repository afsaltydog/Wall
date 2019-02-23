from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re, socket
app = Flask(__name__)
app.secret_key='ASFHWEIhsdjfqwbfiuw98scjk9@$@'
bcrypt = Bcrypt(app)

# our index route will handle rendering our form
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/process', methods=['POST'])
def results():
    print("Got Post Info")
    print(str(request.form))
    
    is_valid = True

    if len(request.form['fname']) < 1:
        flash("This field is required", 'fname')
        is_valid = False
    elif len(request.form['fname']) < 2:
        flash("Please enter a first name", 'fname')
        is_valid = False
    elif not re.match("^[a-zA-Z]+(?:_[a-zA-Z]+)?$", request.form['fname']):
        flash("The first name must be letters only", 'fname')
        is_valid = False

    if len(request.form['lname']) < 1:
        flash("This field is required", 'lname')
        is_valid = False
    elif len(request.form['lname']) < 2:
        flash("The last name needs to be at least two characters", 'lname')
        is_valid = False
    elif not re.match("^[a-zA-Z]+(?:_[a-zA-Z]+)?$", request.form['lname']):
        flash("The last name must be letters only", 'lname')
        is_valid = False
    
    if len(request.form['email']) < 1:
        flash("This field is required", 'email')
        is_valid = False
    elif len(request.form['email']) < 2:
        flash("The email address should be at least two characters", 'email')
        is_valid = False
    
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    if not EMAIL_REGEX.match(request.form['email']):    # test whether a field matches the pattern
        print('email is not valid')
        flash("The email address is not valid", 'email')
        is_valid = False
    else:
        mysql = connectToMySQL('loginRegistration')
        query = "SELECT email FROM Users;"
        emails = mysql.query_db(query)
        print('emails is '+str(emails))
        for e in emails:
            print('e is '+str(e))
            if e['email'] == str(request.form['email']):
                flash("The email address is already being used", 'email')
                is_valid = False
    
    if len(request.form['password']) < 1:
        flash("This field is required", 'pwd')
        is_valid = False
    if len(request.form['confirm']) < 1:
        flash("This field is required", 'confirm')
        is_valid = False
    elif request.form['password'] != request.form['confirm']:
        flash("The passwords do not match", 'pwd')
        is_valid = False
    
    PWD_REGEX = re.compile(r'(?=\D*\d)(?=[^A-Z]*[A-Z])(?=[^a-z]*[a-z])[A-Za-z0-9]{10,}$')
    if not PWD_REGEX.match(request.form['password']):    # test whether a field matches the pattern
        print('The password must contain at least 1 digit, 1 uppercase letter, and 1 lowercase letter, and be greater than 10 characters')
        flash("The password must contain at least 1 digit, 1 uppercase letter, and 1 lowercase letter, and be greater than 10 characters", 'pwd')
        is_valid = False
        
    if is_valid:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        mysql = connectToMySQL('loginRegistration')
        query = "INSERT INTO Users (first_name, last_name, email, password) VALUES (%(fname)s, %(lname)s, %(email)s, %(pwd)s);"
        data = {"fname": request.form['fname'],
                "lname": request.form['lname'],
                "email": request.form['email'],
                "pwd": pw_hash
        }
        print('query is '+str(query))
        new_id = mysql.query_db(query, data)
        flash("DB successfully added! New ID is "+str(new_id), 'regis')
        session['id'] = new_id
        return redirect('/success')
    else:
        print("Something on the form was not valid")

    return redirect('/')

@app.route('/login', methods=['post'])
def login():
    # do stuff for login

    mysql = connectToMySQL('loginRegistration')
    query = "SELECT * FROM Users WHERE email = '"+str(request.form['email'])+"';"
    print('SELECT query is '+query)
    res = mysql.query_db(query)
    print('result is '+str(res))

    if not res:
        flash("You could not be logged in", 'logout')
        return redirect('/')

    # check password hash
    print("request.form[password] is "+str(request.form['password']))
    print("res[0][password] is "+str(res[0]['password']))

    if bcrypt.check_password_hash(res[0]['password'], request.form['password']):
        print("we passed the password validation")
        print("res[0][email] is "+str(res[0]['email']))
        print("request.form[email] is "+str(request.form['email']))
        if res[0]['email'] != request.form['email']:
            flash("You could not be logged in", 'logout')
            return redirect('/')

    first_name = res[0]['first_name']
    print("login first_name "+first_name)

    mysql = connectToMySQL('loginRegistration')
    query = "SELECT id FROM Users WHERE first_name = '"+first_name+"';"
    res = mysql.query_db(query)
    print("login res is "+str(res))

    print("**********res[0]['id'] is "+str(res[0]['id'])+"******************")
    session['id'] = res[0]['id']

    #return render_template('result.html', fname=first_name, dbInfo=res)
    return redirect('/display')

@app.route('/success', methods=['get', 'post'])
def success():
    if 'id' in session:
        id = session['id']
    else:
        flash("You must log in to enter this website", 'logout')
        return redirect('/')

    mysql = connectToMySQL('loginRegistration')
    query = "SELECT * FROM Users WHERE id = "+str(id)+";"
    print('SELECT query is '+query)
    res = mysql.query_db(query)
    print('result is '+str(res))
    first_name = res[0]['first_name']

    mysql = connectToMySQL('loginRegistration')
    query = "SELECT * FROM Users;"
    res = mysql.query_db(query)

    flash("You've been successfully registered", 'success')

    return render_template('result.html', fname=first_name, dbInfo=res)

@app.route('/send', methods=['get', 'post'])
def send_message():
    if 'id' in session:
        id = session['id']
    else:
        flash("You must log in to enter this website", 'logout')
        return redirect('/')

    print("Entering /send...**************")

    if len(str(request.form['message'])) < 5:
        flash("Your message needs to be at least 5 characters long", 'logout')
        return redirect('/display')

    print(str(request.form['recipient_name']))
    mysql = connectToMySQL('loginRegistration')
    query = "SELECT id FROM Users WHERE first_name = "+str(request.form['recipient_name'])+";"
    resid = mysql.query_db(query)
    print("resid is "+str(resid))
    print("resid[0]['id'] is "+str(resid[0]['id']))
    print("id is "+str(id))

    # session['recipient_id'] = str(resid[0]['id']))
    
    # print('result is '+str(res))
    mysql = connectToMySQL('loginRegistration')
    query = "INSERT INTO messages (message, User_id, recipient_id) VALUES (%(msg)s, %(sender)s, %(rec_id)s);"
    data = {"msg": request.form['message'],
            "sender": id,
            "rec_id": resid[0]['id']
    }
    res = mysql.query_db(query, data)   #this res will only give success or failure on inserting 
    
    # /display
   
    
    # return render_template('result.html', fname=first_name, dbInfo=users, msgInfo=msgs, num_o_msg=ctr)
    return redirect('/display')

@app.route('/display', methods=['get', 'post'])
def display():
    if 'id' in session:
        id = session['id']
    else:
        flash("You must log in to enter this website", 'logout')
        return redirect('/')

    print("Entering /display...**************")
    print("id is "+str(id))
    
    # get the first name of the user logged in (also known as sender)
    mysql = connectToMySQL('loginRegistration')
    query = "SELECT first_name FROM Users WHERE id = "+str(id)+";"
    res = mysql.query_db(query)
    first_name = res[0]['first_name']

    print("first_name is "+str(first_name))

    # get the dbInfo for Users for loading all of the users
    mysql = connectToMySQL('loginRegistration')
    query = "SELECT * FROM Users ORDER BY first_name;"
    users = mysql.query_db(query)

    # get the dbInfo for messages
    mysql = connectToMySQL('loginRegistration')
    # query = "SELECT message, messages.created_at, first_name, messages.message_id FROM Users JOIN messages WHERE Users.id = Messages.recipient_id AND Users.id = "+str(id)+";"
    query = "SELECT * FROM Users JOIN messages WHERE Users.id = Messages.recipient_id AND Users.id = "+str(id)+";"
    print("message query is "+str(query))
    # SELECT message, messages.created_at, first_name, messages.message_id FROM loginregistration.users join loginregistration.messages where users.id = messages.recipient_id and users.id = 2;
    msgs = mysql.query_db(query)
    print("msgs is "+str(msgs))
    print("recipient is "+str(msgs[0]['User_id']))

    mysql = connectToMySQL('loginRegistration')
    query = "SELECT first_name FROM Users WHERE Users.id = "+str(msgs[0]['User_id'])+";"
    res = mysql.query_db(query)
    print("res is "+str(res[0]['first_name']))

    ctr = 0
    for x in msgs:
        ctr += 1
        print("ctr = "+str(ctr))

    mysql = connectToMySQL('loginRegistration')
    # query = "SELECT message, messages.created_at, first_name, messages.message_id FROM Users JOIN messages WHERE Users.id = Messages.recipient_id AND Users.id = "+str(id)+";"
    query = "SELECT * FROM messages JOIN Users WHERE Users.id = "+str(id)+";"
    print("message query is "+str(query))
    
    sent_msgs = mysql.query_db(query)
    print("msgs is "+str(sent_msgs))
    
    for m in msgs:
        print("datetime for "+str(m['message'])+" is "+str(m['messages.created_at']))

    ctr2 = 0
    for x in sent_msgs:
        if (x['User_id'] == id):
            ctr2 += 1
    print("ctr = "+str(ctr2))
    
    return render_template('result.html', fname=first_name, dbInfo=users, msgInfo=msgs, num_o_msg=ctr, sender=res[0]['first_name'], msgs_sent=ctr2)

# @app.template_filter('strftime')
# def _jinja2_filter_datetime(date, fmt=None):
    # date = dateutil.parser.parse(date)
    # native = date.replace(tzinfo=None)
    # format='%b %d, %Y'
    # format="EEEE, d. MMMM y 'at' HH:mm"
    # return native.strftime(format) 

@app.route('/delete/<id>', methods=['get', 'post'])
def delete(id):
    print("delete**************")

    # check message's user id to make sure it is the same as the logged in user's id
    mysql =connectToMySQL('loginRegistration')
    query = "SELECT User_id FROM messages JOIN Users WHERE message_id = "+id+";"
    res = mysql.query_db(query)
    if str(res) != str(session['id']):
        return redirect('/warning')

    mysql = connectToMySQL('loginRegistration')
    query = "DELETE FROM messages WHERE messages.message_id = "+str(id)+";"
    res = mysql.query_db(query)
    print("res is "+str(res))

    return redirect('/display')

@app.route('/warning', methods=['GET'])
def warning():
    print("warning**************")

    hostname=socket.gethostname()   
    IPAddr=socket.gethostbyname(hostname)   

    session.clear()

    flash('You have been logged out', 'logout')

    return render_template("warning.html", ip=IPAddr, host=hostname)

@app.route('/logout', methods=['GET','POST'])
def logout():
    print("logout**************")
    
    session.clear()
    flash('You have been logged out', 'logout')

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)