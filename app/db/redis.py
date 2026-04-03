import os
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

try:
    pool = redis.ConnectionPool(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True,
        max_connections=20
    )

    redis_client = redis.Redis(connection_pool=pool)

    redis_client.ping()

    print("✅ Redis connected successfully")

except redis.exceptions.ConnectionError as e:

    print("❌ Redis connection failed:", e)

    redis_client = None


# -----------------------------------------------------
# Utility Functions
# -----------------------------------------------------

def set_cache(key: str, value: str, expire: int = None):
    """
    Store value in Redis cache
    """
    try:
        redis_client.set(name=key, value=value, ex=expire)
    except Exception as e:
        print("Redis set error:", e)


def get_cache(key: str):
    """
    Get value from Redis cache
    """
    try:
        return redis_client.get(key)
    except Exception as e:
        print("Redis get error:", e)
        return None


def delete_cache(key: str):
    """
    Delete key from Redis
    """
    try:
        redis_client.delete(key)
    except Exception as e:
        print("Redis delete error:", e)


def cache_exists(key: str):
    """
    Check if key exists
    """
    try:
        return redis_client.exists(key)
    except Exception:
        return False


def set_json(key: str, value: dict, expire: int = None):
    """
    Store JSON data in Redis
    """
    import json
    redis_client.set(key, json.dumps(value), ex=expire)


def get_json(key: str):
    """
    Retrieve JSON data from Redis
    """
    import json
    data = redis_client.get(key)

    if data:
        return json.loads(data)

    return None


def flush_cache():
    """
    Clear entire Redis cache
    """
    redis_client.flushdb()


def redis_health_check():
    """
    Check Redis connection
    """
    try:
        redis_client.ping()
        return True
    except Exception:
        return False
    
def get_redis_client():
    """
    Return Redis client instance
    """
    if redis_client is None:
        raise Exception("Redis is not connected")
    return redis_client