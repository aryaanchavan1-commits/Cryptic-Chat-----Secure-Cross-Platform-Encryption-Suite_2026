"""
Logging configuration for Cryptic Chat - Secure Cross-Platform Encryption Suite
"""

import logging
import logging.handlers
import os
from config import LOG_FILE, LOG_LEVEL, MAX_LOG_SIZE, BACKUP_COUNT

def setup_logging():
    """Setup logging configuration"""
    
    # Get log level from config
    log_level = getattr(logging, LOG_LEVEL.upper())
    
    # Create logger
    logger = logging.getLogger("CrypticChat")
    logger.setLevel(log_level)
    logger.handlers.clear()
    
    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.error(f"Failed to create log file handler: {e}")
    
    return logger

# Create a global logger instance
logger = setup_logging()

def log_message(level, message):
    """Log a message with specified level"""
    if level == 'DEBUG':
        logger.debug(message)
    elif level == 'INFO':
        logger.info(message)
    elif level == 'WARNING':
        logger.warning(message)
    elif level == 'ERROR':
        logger.error(message)
    elif level == 'CRITICAL':
        logger.critical(message)

def log_exception(exc):
    """Log an exception with stack trace"""
    logger.error(f"Exception occurred: {exc}", exc_info=True)

def get_logger():
    """Get the logger instance"""
    return logger
