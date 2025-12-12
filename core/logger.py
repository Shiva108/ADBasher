import logging
import os
import json
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler
from rich.console import Console

# Initialize Rich Console
console = Console()

class JsonFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings for easier parsing/SIEM integration.
    """
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        # Include exception trace if available
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def setup_logger(session_id: str, log_dir: str, level: str = "INFO"):
    """
    Sets up the global logger for the session.
    
    Args:
        session_id (str): Unique identifier for the current session.
        log_dir (str): Directory to store log files.
        level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    # Create log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    log_file_path = os.path.join(log_dir, f"session_{session_id}.log")
    json_log_file_path = os.path.join(log_dir, f"session_{session_id}.json.log")

    # Root Logger Configuration
    root_log = logging.getLogger()
    root_log.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers to avoid duplicates
    root_log.handlers = []

    # 1. Console Handler (Rich) - Improving UX
    console_handler = RichHandler(console=console, rich_tracebacks=True)
    console_handler.setLevel(getattr(logging, level.upper()))
    console_format = logging.Formatter("%(message)s", datefmt="[%X]")
    console_handler.setFormatter(console_format)
    root_log.addHandler(console_handler)

    # 2. File Handler (Human Readable)
    file_handler = RotatingFileHandler(
        log_file_path, maxBytes=10*1024*1024, backupCount=5 # 10MB file size
    )
    file_handler.setLevel(getattr(logging, level.upper()))
    file_format = logging.Formatter(
        "%(asctime)s - [%(levelname)s] - %(name)s - %(message)s"
    )
    file_handler.setFormatter(file_format)
    root_log.addHandler(file_handler)

    # 3. JSON File Handler (Machine Readable/SIEM)
    json_handler = RotatingFileHandler(
        json_log_file_path, maxBytes=10*1024*1024, backupCount=5
    )
    json_handler.setLevel(logging.INFO) # Always log INFO+ to JSON
    json_formatter = JsonFormatter()
    json_handler.setFormatter(json_formatter)
    root_log.addHandler(json_handler)

    logging.info(f"Logger initialized for session {session_id}")
    logging.info(f"Logs writing to: {log_file_path}")

def get_logger(name: str):
    return logging.getLogger(name)
