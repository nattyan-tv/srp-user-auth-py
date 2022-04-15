import base64
import binascii
import datetime
import hashlib
import hmac
import os
import re

import boto3
import six


init_N = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' \
    + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' \
    + 'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' \
    + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' \
    + 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' \
    + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' \
    + '83655D23DCA3AD961C62F356208552BB9ED529077096966D' \
    + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' \
    + 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' \
    + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' \
    + '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' \
    + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' \
    + 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' \
    + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' \
    + 'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' \
    + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'
g_hex = '2'
info_bits = bytearray('Caldera Derived Key', 'utf-8')


def hex_to_long(hex_string):
    """
    16 進文字列を 10 進整数に変換する
    """
    return int(hex_string, 16)


def long_to_hex(long_num):
    """
    10 進整数を 16 進文字列に変換する
    """
    return f'{long_num:x}'


def pad_hex(long_int):
    """
    16進文字列に変換してから適宜先頭に 0 または 00 を補う
    PAD に相当
    """
    if not isinstance(long_int, six.string_types):
        hash_str = long_to_hex(long_int)
    else:
        hash_str = long_int
    if len(hash_str) % 2 == 1:
        hash_str = f'0{hash_str}'
    elif hash_str[0] in '89ABCDEFabcdef':
        hash_str = f'00{hash_str}'

    return hash_str


def hash_sha256(buf):
    """
    バイト列を sha256 でハッシュ化してから 16 進文字列に変換
    64 文字に満たない場合は先頭を 0 で埋める
    """
    a = hashlib.sha256(buf).hexdigest()

    return (64 - len(a)) * '0' + a


def hex_hash(hex_string):
    """
    16 進文字列を 64 桁のハッシュに変換する
    """
    return hash_sha256(bytearray.fromhex(hex_string))


def calculate_u(A, B):
    """
    u = SHA1(PAD(A) | PAD(B)) を計算する
    SHA1 じゃなくて SHA256 かもしれない
    """
    u_hex_hash = hex_hash(pad_hex(A) + pad_hex(B))

    return hex_to_long(u_hex_hash)


def compute_hkdf(ikm, salt):
    """
    キー導出関数を計算する
    先頭 16 バイト
    """
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    info_bits_update = info_bits + bytearray(chr(1), 'utf-8')
    hmac_hash = hmac.new(prk, info_bits_update, hashlib.sha256).digest()

    return hmac_hash[:16]


def get_now_string():
    """
    現在時刻を取得する
    'Sun Apr 9 07:46:12 UTC 2022'
    のように、day が一桁の場合は十の位をゼロにする点に注意
    """
    return re.sub(
        r" 0(\d) ", r" \1 ",
        datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
    )


class CognitoSRP:
    def __init__(self, username, password, pool_id, client_id, client):
        self.username = username
        self.password = password
        self.pool_id = pool_id
        self.client_id = client_id
        self.client = client if client else boto3.client('cognito-idp')
        self.N = hex_to_long(init_N)
        self.g = hex_to_long(g_hex)
        self.k = hex_to_long(hex_hash('00' + init_N + '0' + g_hex)) # k = SHA1(N | PAD(g))
        self.small_a_value = self.generate_random_small_a()
        self.A = self.calculate_a()


    def generate_random_small_a(self):
        """
        A = g^a % N の a を計算する
        """
        hex_random = binascii.hexlify(os.urandom(128))
        rand_int = hex_to_long(hex_random)
        small_a_int = rand_int % self.N

        return small_a_int


    def calculate_a(self):
        """
        A = g^a % N を計算する
        """
        A = pow(self.g, self.small_a_value, self.N)
        if A % self.N == 0:
            raise ValueError('Illegal paramater. A mod N cannot be 0.')

        return A


    def get_auth_params(self):
        """
        InitiateAuth API の引数
        """
        auth_params = {
            'USERNAME': self.username,
            'SRP_A': long_to_hex(self.A)
        }

        return auth_params


    def authenticate_user(self):
        """
        USER_SRP_AUTH の実行
        """
        auth_params = self.get_auth_params()
        response = self.client.initiate_auth(
            AuthFlow='USER_SRP_AUTH',
            AuthParameters=auth_params,
            ClientId=self.client_id
        )
        if response['ChallengeName'] == 'PASSWORD_VERIFIER':
            challenge_response = self.get_challenge_response(response['ChallengeParameters'])
            response = self.client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName='PASSWORD_VERIFIER',
                ChallengeResponses=challenge_response
            )

            return response


    def get_challenge_response(self, challenge_parameters):
        """
        PASSWORD_VERIFIER_CHALLENGE に必要なレスポンスを生成する
        """
        timestamp = get_now_string()
        user_id_for_srp = challenge_parameters['USER_ID_FOR_SRP']
        server_b_value = hex_to_long(challenge_parameters['SRP_B'])
        salt = hex_to_long(challenge_parameters['SALT'])
        secret_block_b64 = challenge_parameters['SECRET_BLOCK']
        secret_block_bytes = base64.standard_b64decode(secret_block_b64)

        hkdf = self.get_password_authentication_key(
            user_id_for_srp,
            self.password,
            server_b_value,
            salt
        )

        msg = bytearray(self.pool_id.split('_')[1], 'utf-8') + \
            bytearray(user_id_for_srp, 'utf-8') + \
            bytearray(secret_block_bytes) + \
            bytearray(timestamp, 'utf-8')
        hmac_hash = hmac.new(hkdf, msg, hashlib.sha256).digest()
        signature_string = base64.standard_b64encode(hmac_hash)

        challenge_response = {
            'TIMESTAMP': timestamp,
            'USERNAME': user_id_for_srp,
            'PASSWORD_CLAIM_SECRET_BLOCK': secret_block_b64,
            'PASSWORD_CLAIM_SIGNATURE': signature_string.decode('utf-8')
        }

        return challenge_response


    def get_password_authentication_key(self, username, password, server_b_value, salt):
        """
        ハッシュ化用のキーを生成する
        """
        if server_b_value % self.N == 0:
            raise ValueError('B cannot be zero.')

        u_value = calculate_u(self.A, server_b_value)
        if u_value == 0:
            raise ValueError('U cannot be zero.')

        username_password = '{0}{1}:{2}'.format(
            self.pool_id.split('_')[1], username, password
        )
        username_password_hash = hash_sha256(bytearray(username_password, 'utf-8'))
        # username_password_hash = hash_sha256(username_password.encode('utf-8')) # 同じ

        x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
        int_value2 = server_b_value - self.k * pow(self.g, x_value, self.N)
        # (B - (k * g^x)) ^ (a + (u * x)) % N を実行している
        s_value = pow(int_value2, self.small_a_value + u_value * x_value, self.N)
        hkdf = compute_hkdf(
            bytearray.fromhex(pad_hex(s_value)),
            bytearray.fromhex(pad_hex(long_to_hex(u_value)))
        )

        return hkdf
