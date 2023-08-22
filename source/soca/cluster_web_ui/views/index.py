######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################
import datetime
import os
import json
import logging
import config
import cognito_auth
import boto3
from botocore import config as botocore_config
from decorators import login_required
from flask import render_template, request, redirect, session, flash, Blueprint, current_app
from requests_aws4auth import AWS4Auth
from requests import post, get
from elasticsearch import Elasticsearch, RequestsHttpConnection


logger = logging.getLogger("application")
index = Blueprint('index', __name__, template_folder='templates')
SOCA_USER_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "user": {"type": "keyword"},
            "loginTime": {"type": "date"},
            "sudoers": {"type": "boolean"}
        }
    }
}


def boto_extra_config():
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/2.7.2"}
    return botocore_config.Config(**aws_solution_user_agent)


def get_soca_configuration():
    secretsmanager_client = boto3.client('secretsmanager',config=boto_extra_config())
    configuration_secret_name = os.environ['SOCA_CONFIGURATION']
    response = secretsmanager_client.get_secret_value(SecretId=configuration_secret_name)
    return json.loads(response['SecretString'])


soca_configuration = get_soca_configuration()
es_endpoint = 'https://' + soca_configuration['ESDomainEndpoint']
users_es_index_name = "soca_users"


def get_es_client():
    boto3_session = boto3.Session()
    credentials = boto3_session.get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, boto3_session.region_name, 'es',
                       session_token=credentials.token)
    es = Elasticsearch([es_endpoint], port=443, http_auth=awsauth, use_ssl=True, verify_certs=True,
                       connection_class=RequestsHttpConnection)
    return es


@index.route('/ping', methods=['GET'])
def ping():
    return "Alive", 200


@index.route('/', methods=['GET'])
@login_required
def home():
    user = session['user']
    sudoers = session['sudoers']
    return render_template('index.html', user=user, sudoers=sudoers)


@index.route('/login', methods=['GET'])
def login():
    redirect = request.args.get("fwd", None)
    if redirect is None:
        return render_template('login.html', redirect=False)
    else:
        return render_template('login.html', redirect=redirect)


@index.route('/logout', methods=['GET'])
@login_required
def logout():
    session_data = ["user", "sudoers", "api_key"]
    user = session['user']
    for param in session_data:
        session.pop(param, None)
    # 退出登录，es 删除数据
    # es = get_es_client()
    # es.delete_by_query(index=users_es_index_name, body={'query': {'bool': {'must': {'term': {'user': user}}}}}),
    return redirect('/')


@index.route('/robots.txt', methods=['GET'])
def robots():
    # in case SOCA is accidentally set to wide open, this prevent the website to be indexed on Search Engine
    return "Disallow: /"

@index.route('/auth', methods=['POST'])
def authenticate():
    user = request.form.get('user')
    password = request.form.get('password')
    redirect_path = request.form.get('redirect')
    logger.info("Received login request for : " + str(user))
    if user is not None and password is not None:
        check_auth = post(config.Config.FLASK_ENDPOINT + '/api/ldap/authenticate',
                          headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                          data={"user": user, "password": password},
                          verify=False) # nosec
        logger.info(check_auth)
        if check_auth.status_code != 200:
            flash(check_auth.json()['message'])
            return redirect('/login')
        else:
            session['user'] = user.lower()
            logger.info("User authenticated, checking sudo permissions")
            check_sudo_permission = get(config.Config.FLASK_ENDPOINT + '/api/ldap/sudo',
                                        headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                        params={"user": user},
                                        verify=False) # nosec
            if check_sudo_permission.status_code == 200:
                session["sudoers"] = True
            else:
                session["sudoers"] = False

            # 登录成功，往 es 写数据
            # doc_type = "item"
            # es = get_es_client()
            # add = es.index(index=users_es_index_name, doc_type=doc_type, body={'user': user,
            #                                                                    'loginTime': datetime.datetime.now(),
            #                                                                    'sudoers': session["sudoers"]})
            # logger.info("success add user " + user + " to es : " + json.dumps(add))
            if redirect_path is not None:
                return redirect(redirect_path)
            else:
                return redirect("/")

    else:
        return redirect('/login')

@index.route('/oauth', methods=['GET'])
def oauth():
    next_url = request.args.get('state')
    sso_auth = cognito_auth.sso_authorization(request.args.get('code'))
    cognito_root_url = config.Config.COGNITO_ROOT_URL
    if sso_auth['success'] is True:
        logger.info("User authenticated, checking sudo permissions")
        check_sudo_permission = get(config.Config.FLASK_ENDPOINT + '/api/ldap/sudo',
                                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                    params={"user": session["user"]},
                                    verify=False) # nosec
        if check_sudo_permission.status_code == 200:
            session["sudoers"] = True
        else:
            session["sudoers"] = False

        if next_url:
            return redirect(cognito_root_url+next_url)
        else:
            return redirect(cognito_root_url)
    else:
        if sso_auth['message'] == 'user_not_found':
            flash("This user does not seems to have an account on SOCA", "error")
        else:
            flash(str(sso_auth['message']), "error")
        return redirect("/login")

