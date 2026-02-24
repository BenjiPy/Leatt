"""Leatt - Main entry point."""

import sys
import signal
import argparse
from pathlib import Path

from .utils.logger import setup_logging, get_logger
from .utils.config import get_config
from .utils.platform import PlatformUtils
from .core.daemon import LeattDaemon


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="leatt",
        description="Leatt - Data Leak Prevention for individuals",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    
    parser.add_argument(
        "--no-systray",
        action="store_true",
        help="Run without systray interface (background only)",
    )
    
    parser.add_argument(
        "--web",
        action="store_true",
        help="Enable web dashboard",
    )
    
    parser.add_argument(
        "--config-dir",
        type=Path,
        help="Path to configuration directory",
    )
    
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()
    
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(log_level=log_level)
    
    logger = get_logger("main")
    config = get_config()
    
    logger.info(f"Starting {config.app_name} v{config.app_version}")
    
    system_info = PlatformUtils.get_system_info()
    logger.info(f"OS: {system_info.os.value} ({system_info.os_version})")
    logger.info(f"User: {system_info.username}@{system_info.hostname}")
    logger.info(f"Admin privileges: {system_info.is_admin}")
    
    if config.learning_mode:
        logger.info("Learning mode is ENABLED - building baseline behavior")
    
    daemon = LeattDaemon(
        enable_systray=not args.no_systray,
        enable_web=args.web or config.web_enabled,
    )
    
    def signal_handler(signum, frame):
        logger.info("Shutdown signal received")
        daemon.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        daemon.start()
        return 0
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        daemon.stop()
        return 0
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
