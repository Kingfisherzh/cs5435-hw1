from csv import reader

from app.models.breaches import (
    create_plaintext_breach_entry,
    create_hashed_breach_entry,
    create_salted_breach_entry,
    get_breaches
)

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breaches(db, username):
    with open(PLAINTEXT_BREACH_PATH) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        for creds in r:
            create_plaintext_breach_entry(db, creds[0], creds[1])
    with open(HASHED_BREACH_PATH) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert (header[0] == 'username')
        for creds in r:
            create_hashed_breach_entry(db, creds[0], creds[1])
    with open(SALTED_BREACH_PATH) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert (header[0] == 'username')
        for creds in r:
            create_salted_breach_entry(db, creds[0], creds[1])

    plaintext_breaches, hashed_breaches, salted_breaches = get_breaches(db, username) # .all()函数返回的大概是整行
    passwords = list()
    for pairs in plaintext_breaches:
        passwords.append(pairs.password) # 用dot寻找对应label的用法有搜到，但是不知道用过来对不对
    for pairs in hashed_breaches:
        passwords.append(pairs.hashed_password)
    for pairs in salted_breaches:
        passwords.append(pairs.salted_password)
    return passwords

