# cognito-srp-auth-python

https://github.com/capless/warrant の中身を理解したいので、部分的に写経していく

読み解いた内容は現在 [Cognito の USER_SRP_AUTH を Python で理解したい](https://kesumita.hatenablog.com/entry/2022/04/29/155048) に書いています。

## 使い方

- .env ファイルの作成

```sh
$ cp .env.sample .env
$ vi .env
```

中身は以下の通りです。

```
client_id=xxx
userpool_id=xxxx
username=xxxx
password= xxxx
```

- ライブラリのインストール

```sh
$ pip install pipenv
$ pipenv install
$ pipenv shell
```

外部ライブラリは boto3 だけですが、 .env ファイルを読み込むためにも Pipenv を使っています。

- ログインの実行

```sh
$ python main.py
```

ログインが実行され、標準出力に各種トークンが出力されます。

## 現時点のモジュール構成

- .env.sample
- main.py
- srp.py

### srp.py

[aws_srp](https://github.com/capless/warrant/blob/master/warrant/aws_srp.py) をかいつまんで写経しています。

CognitoSRP クラスの authenticate_user メソッドで、ログインができます。

### main.py

authenticate_user() 関数と main() 関数を定義しています。

main() 関数は CognitoSRP クラスの authenticate_user メソッドを呼び出して一発でログインします。

authenticate_user() 関数は、authenticate_user メソッドを各ステップに分けて実行しているだけです。

備忘録的に認証フローの流れをわかりやすく書き下しているだけであり、中身の処理は全く同じです。

