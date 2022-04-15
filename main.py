import boto3
import os

from dotenv import load_dotenv
from srp import CognitoSRP


load_dotenv('.env')

cognito_idp = boto3.client('cognito-idp')

client_id = os.environ['client_id']
userpool_id = os.environ['userpool_id']
username = os.environ['username']
password = os.environ['password']


def authenticate_user():
    # 大枠の流れだけ抜き出したもの
    srp = CognitoSRP(
        username=username,
        password=password,
        pool_id=userpool_id,
        client_id=client_id,
        client= cognito_idp,
    )
    srp_a = srp.get_auth_params()['SRP_A']
    response = cognito_idp.initiate_auth(
        AuthFlow='USER_SRP_AUTH',
        AuthParameters={
            'SRP_A': srp_a,
            'USERNAME': username
        },
        ClientId=client_id
    )
    challenge_parameters = response['ChallengeParameters']
    challenge_response = srp.get_challenge_response(challenge_parameters)
    response = cognito_idp.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName='PASSWORD_VERIFIER',
        ChallengeResponses=challenge_response
    )
    return response['AuthenticationResult']


def main():
    srp = CognitoSRP(
        username=username,
        password=password,
        pool_id=userpool_id,
        client_id=client_id,
        client= cognito_idp,
    )
    response = srp.authenticate_user()  # これだけで良い
    return response['AuthenticationResult']

if __name__ == '__main__':
    # どっちも同じ
    res = authenticate_user()
    # res = main()
    print(res)
