# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
"""
#####################################
##           Gherkin               ##
#####################################
Rule Name:
    IAM_ROLE_NOT_USED
Description:
    Checks that an AWS IAM Role is being used in the last X days, default value is 90 days. The rule is NON-COMPLIANT if an AWS IAM Role is not used within the last X days.
Rationale:
    Ensures that no AWS IAM Role is unused beyond "x" number of days, default is 90 days.
Indicative Severity:
    Low
Trigger:
    Periodic
Reports on:
    AWS::IAM::Role
Rule Parameters:
    DaysBeforeUnused
    (Optional) Number of days when the AWS IAM Roles are considered unused (default 90 days).
    If the value is 0, IAM Roles must be used at least once every 24 hours.
Scenarios:
    Scenario: 1
        Given: Atleast one or more IAM roles are present
        And: Rule parameter DaysBeforeUnused is not specified
        Then: Returns parameter with DaysBeforeUnused set to default 90 days.
    Scenario: 2
        Given: Atleast one or more IAM roles are present
        And: Rule parameter DaysBeforeUnused is not a positive integer
        Then: Return ERROR
    Scenario: 3
        Given: Atleast one or more IAM roles are present
        And: Rule parameter DaysBeforeUnused specified with positive integer
        And: no IAM Role is unused from last DaysBeforeUnused days
        Then: Return COMPLIANT
    Scenario: 4
        Given: Atleast one or more IAM roles are present
        And: Rule parameter DaysBeforeUnused specified with positive integer
        And: One or more IAM Role is unused from last DaysBeforeUnused days
        Then: Return NON_COMPLIANT
 """
from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType, InvalidParametersError
from time import sleep
from datetime import datetime, timezone

IAM_THROTTLE_PERIOD = 0.1
DEFAULT_DAYS = 90
CURRENT_TIME = datetime.now(timezone.utc)
APPLICABLE_RESOURCES = ['AWS::IAM::Role']

class IAM_ROLE_NOT_USED(ConfigRule):
    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        evaluations = []
        iam_client = client_factory.build_client(service='iam')
        for role_data in get_roles(iam_client):
            role_name = role_data.get('RoleName')
            last_used = role_data.get('RoleLastUsed')
            if last_used:
                diff = (CURRENT_TIME - last_used.get('LastUsedDate')).days
            else:
                created_on = role_data.get('CreateDate')
                diff = (CURRENT_TIME - created_on).days
            days_before_unused = valid_rule_parameters.get('DaysBeforeUnused')
            # Scenario:3 Atleast one or more IAM roles are present and IAM role is in use within DaysBeforeUnused
            if diff <= days_before_unused:
                evaluations.append(Evaluation(ComplianceType.COMPLIANT, role_name, APPLICABLE_RESOURCES[0]))
                # Scenario:4 Atleast one or more IAM roles are present and IAM role is not in use within DaysBeforeUnused
            else:
                evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT, role_name, APPLICABLE_RESOURCES[0],
                                            annotation="This AWS IAM Role has not been used within the last {} day(s)".format(days_before_unused)))
        return evaluations

    def evaluate_parameters(self, rule_parameters):
        # Scenario:1 Rule parameters are optional (not specified)
        if not rule_parameters.get('DaysBeforeUnused'):
            rule_parameters['DaysBeforeUnused'] = DEFAULT_DAYS

        # Scenario:2 Rule parameter is not positive integer
        # The int() function will raise an error if the string configured can't be converted to an integer
        try:
            rule_parameters['DaysBeforeUnused'] = int(rule_parameters['DaysBeforeUnused'])
        except ValueError:
            raise InvalidParametersError('The parameter "DaysBeforeUnused" must be a integer')

        if rule_parameters['DaysBeforeUnused'] < 0:
            raise InvalidParametersError('The parameter "DaysBeforeUnused" must be greater than or equal to 0')
        return rule_parameters

def get_roles(iam_client):
    roles = []
    roles_result = iam_client.get_paginator('list_roles')
    page_iterator = roles_result.paginate(PaginationConfig={'MaxItems': 100})
    for page in page_iterator:
        roles.extend(page['Roles'])
        sleep(IAM_THROTTLE_PERIOD)
    return roles

################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = IAM_ROLE_NOT_USED()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
