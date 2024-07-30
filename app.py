from flask import Flask,render_template,request
import logging
from feature_extraction import * 
import pickle
def doQuery( conn,test_url ):
        cur = conn.cursor()
        sql="SELECT url FROM verified_online WHERE url='"+test_url+"';"
        cur.execute(sql)
        result=cur.fetchall()
        if result:
            return 1
app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/getURL',methods=['GET','POST'])
def getURL():
    
    test_url = request.form['url']
    hostname = 'localhost'
    username = 'root'
    password = ''
    database = 'flask_app'
    print( "Using mysqlclient (MySQLdb):" )
    #import mysql.connector
    #conn = mysql.connector.connect( host=hostname, user=username, passwd=password, db=database )
    #in_blacklist=doQuery( conn,test_url )
    in_blacklist=None
    #conn.close()

    if in_blacklist:
        value="URL found in blacklist.<br>Phishing"
    else:
        url_feature=feature_extractor(test_url)
        predicted_value=url_feature.extract()
        print(predicted_value)
        if predicted_value[0] == 0:    
            value = "Legitimate"
        else:
            value = "Phishing"
    return render_template("index.html",error=value)
        
if __name__ == "__main__":
    app.run(debug=True)