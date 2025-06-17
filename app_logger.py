import logging
import os
import sys
import threading

log_dir = os.path.join(os.path.expanduser('~'), '.betty')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'app.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def handle_exception(exc_type, exc_value, exc_traceback):
    """Log uncaught exceptions instead of silently exiting."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.critical("Excepción no controlada", exc_info=(exc_type, exc_value, exc_traceback))


sys.excepthook = handle_exception

# Also capture exceptions in background threads (Python 3.8+)
def thread_exception_handler(args):
    logger.critical(
        "Excepción no controlada en hilo",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )

if hasattr(threading, "excepthook"):
    threading.excepthook = thread_exception_handler
