# -*- coding: utf-8 -*-
"""
Created on Tue Mar  2 10:05:27 2021

@author: USER
"""
#importing libraries


import pandas as pd
import ipaddress
import pickle
import re
import sys
from feature_extraction import *
def train(classifier):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import confusion_matrix, accuracy_score
    from sklearn.model_selection import train_test_split
    from sklearn.tree import DecisionTreeClassifier
    from sklearn import svm
    #Loading the data
    legitimate_urls = pd.read_csv("legitimateurl.csv")
    phishing_urls = pd.read_csv("phishingurl.csv")
    raw_data=legitimate_urls.append(phishing_urls)
    
    def protocol_add(url):
        if not (re.match("http://", str(url))or re.match("https://", str(url))) :
            default_protocol = "http://" + str(url)
            return default_protocol
        else:
            return url
        
    raw_data['URL']=raw_data['URL'].apply(protocol_add)
    protocol = raw_data['URL'].str.split("://",1,expand = True)
    feature_dataset=pd.DataFrame()
    domain_address = protocol[1].str.split("/",1,expand=True)
    feature_dataset['domain']=domain_address[0]
    feature_dataset['address']=domain_address[1]
    feature_dataset['is_phished'] = pd.Series(raw_data['Target'], index=feature_dataset.index)
    feature_dataset['long_url'] = raw_data['URL'].apply(long_url)
    feature_dataset['having_@_symbol'] = raw_data['URL'].apply(have_at_symbol)
    feature_dataset['redirection'] = feature_dataset['address'].apply(redirection)
    feature_dataset['dash_in_domain'] = feature_dataset['domain'].apply(dash_in_domain)
    feature_dataset['sub_domains'] = feature_dataset['domain'].apply(sub_domains)
    feature_dataset['ip_in_url'] = feature_dataset['domain'].apply(ip_in_url)
    feature_dataset['shortened']=raw_data['URL'].apply(shortening_service)
    feature_dataset['https_token']=feature_dataset['address'].apply(https_token)
    
    x = feature_dataset.columns[3:11]
    y = pd.factorize(feature_dataset['is_phished'])[0]
    #test-train split
    x_train,x_test,y_train,y_test=train_test_split(feature_dataset[x],y,random_state=0,test_size=0.3)
    actual = y_test
    
    ### Classification of URLs using Decision Tree
    if classifier==1:
        model = DecisionTreeClassifier(max_depth=10)
        model.fit(x_train,y_train)
        pred_label = model.predict(x_test)
        from sklearn.metrics import confusion_matrix,accuracy_score
        cm = confusion_matrix(y_test,pred_label)
        print(accuracy_score(actual,pred_label))
        filename = 'dt'+'.sav'
        pickle.dump(model, open(filename, 'wb'))
        print(list(zip(feature_dataset[x], model.feature_importances_)))

    ### Classification of URLs using SVM
    elif classifier==2:
        svm_clf = svm.SVC(kernel='linear',probability=True) # Linear Kernel
        svm_clf.fit(x_train, y_train)
        y_pred = svm_clf.predict(x_test)
        filename = 'svm'+'.sav'
        pickle.dump(svm_clf, open(filename, 'wb'))
        print(accuracy_score(actual,y_pred))
    
    ### Classification of URLs using Random Forest    
    elif classifier==3:
        clf = RandomForestClassifier(n_estimators=500,max_depth=30,max_features=0.1,max_leaf_nodes=10000)
        clf.fit(x_train, y_train)
        preds = clf.predict(x_test)
        acc=accuracy_score(actual,preds) #accuracy of classifier
        filename = 'rf'+'.sav'
        pickle.dump(clf, open(filename, 'wb'))
        print(accuracy_score(actual,preds))
        print(list(zip(feature_dataset[x], clf.feature_importances_)))

def predictor(splitted_data, classifier_type):
    # Load the model from disk based on the classifier type
    filename = f'{classifier_type}.sav'
    loaded_model = pickle.load(open(filename, 'rb'))
    x = splitted_data.columns[2:10]
    global preds
    preds = loaded_model.predict(splitted_data[x])
    score = loaded_model.predict_proba(splitted_data[x])
    return int(preds[0]), str(score[0][preds[0]])


'''
print("----PHISHING URL DETECTOR - TRAINING----")
print("MENU")
print("\t1.DECISION TREE\n\t2.SUPPORT VECTOR MACHINE\
          \n\t3.RANDOM FOREST\n\t4.EXIT")
          
clf=eval(input())
if clf==1:
    train(1)
elif clf==2:
    train(2)
elif clf==3:
    train(3)
elif clf==4:    
    sys.exit()
'''





