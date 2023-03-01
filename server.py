from flask import Flask, request, render_template, redirect, make_response
import hashlib
import mysql.connector

app = Flask(__name__)
app.secret_key = "secret_key"

# connect to the database
cnx = mysql.connector.connect(user='root', password='password', host='localhost', database='mydb')
cursor = cnx.cursor()

@app.route('/')
def index():
    # check if user is logged in
    if 'session_id' in request.cookies:
        session_id = request.cookies.get('session_id')
        query = "SELECT * FROM sessions WHERE session_id = %s"
        cursor.execute(query, (session_id,))
        result = cursor.fetchone()
        if result:
            # user is logged in, show the home page
            return render_template('index.html')
    
    # user is not logged in, redirect to login page
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # check if user is already logged in
    if 'session_id' in request.cookies:
        session_id = request.cookies.get('session_id')
        query = "SELECT * FROM sessions WHERE session_id = %s"
        cursor.execute(query, (session_id,))
        result = cursor.fetchone()
        if result:
            # user is already logged in, redirect to home page
            return redirect('/')
    
    # check if user submitted the login form
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # hash the password
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        # check if the username and password are correct
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, hashed_password))
        result = cursor.fetchone()
        
        if result:
            # the username and password are correct, set a session cookie
            session_id = hashlib.sha256(username.encode('utf-8')).hexdigest()
            query = "INSERT INTO sessions (session_id, username) VALUES (%s, %s)"
            cursor.execute(query, (session_id, username))
            cnx.commit()
            response = make_response(redirect('/'))
            response.set_cookie('session_id', session_id)
            return response
        
        # the username and password are incorrect, show an error message
        return render_template('login.html', error='Invalid username or password')
    
    # user is not logged in, show the login page
    return render_template('login.html')

@app.route('/logout')
def logout():
    # check if user is logged in
    if 'session_id' in request.cookies:
        session_id = request.cookies.get('session_id')
        query = "SELECT * FROM sessions WHERE session_id = %s"
        cursor.execute(query, (session_id,))
        result = cursor.fetchone()
        if result:
            # user is logged in, delete the session cookie and remove the session from the database
            response = make_response(redirect('/login'))
            response.delete_cookie('session_id')
            query = "DELETE FROM sessions WHERE session_id = %s"
            cursor.execute(query, (session_id,))
            cnx.commit()
            return response
    
    # user is not logged in, redirect to login page
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
