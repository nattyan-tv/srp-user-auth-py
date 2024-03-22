import os

from getpass import getpass

from srp import CognitoSRP, AuthenticationResult

client_id = os.environ['client_id']
userpool_id = os.environ['userpool_id']

def main(username: str, password: str) -> AuthenticationResult:
    srp = CognitoSRP(
        username=username,
        password=password,
        pool_id=userpool_id,
        client_id=client_id,
    )
    response = srp.authenticate_user()
    return response['AuthenticationResult']

if __name__ == '__main__':
    username = input('Username: ')
    password = getpass('Password: ')
    print(main(username, password))
