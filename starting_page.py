from flask import Flask,render_template,jsonify,request,redirect,send_from_directory,url_for
import json
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from flask_bootstrap import Bootstrap
from requests.auth import HTTPBasicAuth
from fmc_change_policy import fmc_login,get_files_assignment,get_ips_assignment,get_policy_assignment
from fmc_change_policy import get_policy_assignment_with_names,get_rules_assignment,get_rules_with_names_assignment
from fmc_change_policy import get_variable_assignment,modify_all_rules,modify_some_rules

app = Flask(__name__)
app.config["UPLOAD_FOLDER"]="/Desktop/flask/"
app.config['SECRET_KEY'] = 'secret!'


user_fmc = ""
passwd_fmc = ""
ip_fmc =""


###



@app.route('/')
def start():
    return redirect("/fmc_start_page")



#pagina de inicio de acceso a FMC
@app.route("/fmc_start_page",methods = ["POST","GET"])
def fmc_starting_page():
    # generar token de fmc con uuid
    #fmc_login esta en fmc_change_policy.py

    global user_fmc
    global passwd_fmc
    global addr_fmc

    if request.method == "GET":
        if user_fmc == "":
            return render_template("login_fmc.html")
        else:
            respuesta_fmc = fmc_login(user_fmc,passwd_fmc,addr_fmc)
            token_auth = respuesta_fmc["X-auth-access-token"]
            token_refresh = respuesta_fmc['X-auth-refresh-token']
            uuid_fmc = respuesta_fmc["DOMAIN_UUID"]

            lista_de_policy_with_names = get_policy_assignment_with_names(addr_fmc,uuid_fmc,token_auth)
            #print(lista_de_policy_with_names)

            lista_de_ips=get_ips_assignment(addr_fmc,uuid_fmc,token_auth)
            #print(lista_de_ips)

            lista_de_rules_with_names = get_rules_with_names_assignment(addr_fmc,uuid_fmc,lista_de_policy_with_names, token_auth)
            #print(lista_de_rules_with_names)
            lista_de_files=get_files_assignment(addr_fmc,uuid_fmc,token_auth)
            #print(lista_de_files)

            lista_de_variables=get_variable_assignment(addr_fmc,uuid_fmc,token_auth)
            #print(lista_de_variables)
            return render_template("select_fmc_rules.html",lista_de_politicas=json.dumps(lista_de_policy_with_names), lista_de_ips =json.dumps(lista_de_ips), lista_de_files =json.dumps(lista_de_files), lista_de_rules = json.dumps(lista_de_rules_with_names), lista_de_variables = json.dumps(lista_de_variables) )
    if request.method == "POST":
        addr_fmc = request.form["ip"]
        user_fmc = request.form["user"]
        passwd_fmc = request.form["passwd"]
        #return(f"hello {user}")


        respuesta_fmc = fmc_login(user_fmc,passwd_fmc,addr_fmc)
        token_auth = respuesta_fmc["X-auth-access-token"]
        token_refresh = respuesta_fmc['X-auth-refresh-token']
        uuid_fmc = respuesta_fmc["DOMAIN_UUID"]

        lista_de_policy_with_names = get_policy_assignment_with_names(addr_fmc,uuid_fmc,token_auth)
        #print(lista_de_policy_with_names)

        lista_de_ips=get_ips_assignment(addr_fmc,uuid_fmc,token_auth)
        #print(lista_de_ips)

        lista_de_rules_with_names = get_rules_with_names_assignment(addr_fmc,uuid_fmc,lista_de_policy_with_names, token_auth)
        #print(lista_de_rules_with_names)
        lista_de_files=get_files_assignment(addr_fmc,uuid_fmc,token_auth)
        #print(lista_de_files)

        lista_de_variables=get_variable_assignment(addr_fmc,uuid_fmc,token_auth)
        #print(lista_de_variables)
        return render_template("select_fmc_rules.html",lista_de_politicas=json.dumps(lista_de_policy_with_names), lista_de_ips =json.dumps(lista_de_ips), lista_de_files =json.dumps(lista_de_files), lista_de_rules = json.dumps(lista_de_rules_with_names), lista_de_variables = json.dumps(lista_de_variables) )


@app.route("/fmc_change_policy",methods=["POST","GET"])
def fmc_change_policy():
    global user_fmc
    global passwd_fmc
    global addr_fmc


    if request.method == "POST":
        #print(request.form.getlist("mySelect"))
        #print(request.form.getlist("ips_select"))

        pol = request.form["mySelect"]
        ips = request.form["ips_select"]
        files = request.form["files_select"]
        rules = request.form.getlist("rules_select")
        logBegin = request.form["logBegin_select"]
        logEnd = request.form["logEnd_select"]
        variable_set = request.form["var_select"]

        respuesta_fmc = fmc_login(user_fmc,passwd_fmc,addr_fmc)
        token_auth = respuesta_fmc["X-auth-access-token"]
        token_refresh = respuesta_fmc['X-auth-refresh-token']
        uuid_fmc = respuesta_fmc["DOMAIN_UUID"]

        lista_de_policy = get_policy_assignment(addr_fmc,uuid_fmc,token_auth)

        lista_de_policy_with_names = get_policy_assignment_with_names(addr_fmc,uuid_fmc,token_auth)

        lista_de_rules = get_rules_assignment(addr_fmc,uuid_fmc,lista_de_policy, token_auth)

        lista_de_ips=get_ips_assignment(addr_fmc,uuid_fmc,token_auth)

        lista_de_files=get_files_assignment(addr_fmc,uuid_fmc,token_auth)

        lista_de_variables=get_variable_assignment(addr_fmc,uuid_fmc,token_auth)

        if len(rules)==0:
            modify_all_rules(user_fmc,passwd_fmc,addr_fmc,uuid_fmc,lista_de_policy_with_names,lista_de_rules, lista_de_ips,lista_de_files,lista_de_variables, pol,ips,files, variable_set)
            return redirect("/fmc_start_page")
        else:
            modify_some_rules(user_fmc,passwd_fmc,addr_fmc,uuid_fmc,lista_de_policy_with_names,lista_de_rules, lista_de_ips,lista_de_files,lista_de_variables, pol,rules,ips,files,logBegin,logEnd, variable_set)
            return redirect("/fmc_start_page")
        return redirect("/fmc_start_page")

    if request.method == "GET":
        return redirect("/fmc_start_page")


if __name__=="__main__":
    app.run(port=5000, host= "0.0.0.0",debug=True)
