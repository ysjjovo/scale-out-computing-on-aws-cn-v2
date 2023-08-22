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

import logging
import config
from decorators import login_required
from flask import Blueprint, render_template, session
import read_secretmanager

logger = logging.getLogger("application")
dashboard = Blueprint('dashboard', __name__, template_folder='templates')


@dashboard.route('/dashboard', methods=['GET'])
@login_required
def index():
    loadbalancer_dns_name = read_secretmanager.get_soca_configuration()['LoadBalancerDNSName']
    kibana_url = "https://" + loadbalancer_dns_name + "/_plugin/kibana/"
    user = session['user']
    if user == 'designer1':
        dashboard_key = config.Config.DESIGN_1_KIBANA_DASHBOARD
    elif user == 'designer2':
        dashboard_key = config.Config.DESIGN_2_KIBANA_DASHBOARD
    else:
        dashboard_key = config.Config.KIBANA_DASHBOARD
    return render_template("dashboard.html",
                           user=session["user"],
                           sudoers=session['sudoers'],
                           kibana_url=kibana_url,
                           dashboard_key=dashboard_key)
