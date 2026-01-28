import bcrypt
import hashlib


def hash_password(password: str) -> str:
    """
    Надежное хеширование пароля с обязательным пре-хешем SHA-256
    """
    # 1. Всегда применяем SHA-256
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # 2. Преобразуем в bytes
    password_bytes = sha256_hash.encode('utf-8')

    # 3. Генерируем соль и хешируем
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)

    # 4. Возвращаем как строку
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверка пароля
    """
    # Применяем тот же SHA-256
    sha256_hash = hashlib.sha256(plain_password.encode('utf-8')).hexdigest()
    password_bytes = sha256_hash.encode('utf-8')

    # Хешированный пароль должен быть в bytes
    hashed_bytes = hashed_password.encode('utf-8')

    # Проверяем
    return bcrypt.checkpw(password_bytes, hashed_bytes)