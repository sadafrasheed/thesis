import time
from lib.common import log

def profile(func):
    def wrapper(*args, **kwargs):
        tracemalloc.start()
        t0 = time.time()

        result = func(*args, **kwargs)

        t1 = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        log(
            f"{func.__name__} took {t1 - t0:.6f}s, "
            f"allocated {current/1024:.1f} KB (peak {peak/1024:.1f} KB)"
        )
        return result
    return wrapper
