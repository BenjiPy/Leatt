"""Leatt - Main entry point."""

import sys
import signal
import argparse
import threading
import time
import os
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
    
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run performance benchmark (monitor CPU, Memory, Disk usage)",
    )
    
    parser.add_argument(
        "--benchmark-duration",
        type=int,
        default=60,
        help="Benchmark duration in seconds (default: 60)",
    )
    
    return parser.parse_args()


class PerformanceMonitor:
    """Monitor Leatt's own resource usage."""
    
    def __init__(self, duration: int = 60):
        import psutil
        self.duration = duration
        self.process = psutil.Process(os.getpid())
        self.running = False
        self.samples: list[dict] = []
        self._thread: threading.Thread | None = None
    
    def start(self):
        """Start monitoring in background thread."""
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print(f"\n{'='*60}")
        print("🔬 PERFORMANCE BENCHMARK STARTED")
        print(f"{'='*60}")
        print(f"Duration: {self.duration}s | Sampling every 1s")
        print(f"PID: {os.getpid()}")
        print(f"{'='*60}\n")
    
    def _monitor_loop(self):
        """Collect performance samples."""
        import psutil
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < self.duration:
            try:
                cpu_percent = self.process.cpu_percent(interval=0.1)
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                
                io_counters = self.process.io_counters() if hasattr(self.process, 'io_counters') else None
                read_mb = io_counters.read_bytes / (1024 * 1024) if io_counters else 0
                write_mb = io_counters.write_bytes / (1024 * 1024) if io_counters else 0
                
                threads = self.process.num_threads()
                
                sample = {
                    "timestamp": time.time() - start_time,
                    "cpu_percent": cpu_percent,
                    "memory_mb": memory_mb,
                    "read_mb": read_mb,
                    "write_mb": write_mb,
                    "threads": threads,
                }
                self.samples.append(sample)
                
                elapsed = int(time.time() - start_time)
                remaining = self.duration - elapsed
                bar_len = 30
                filled = int(bar_len * elapsed / self.duration)
                bar = "█" * filled + "░" * (bar_len - filled)
                
                print(f"\r⏱ [{bar}] {elapsed}s/{self.duration}s | "
                      f"CPU: {cpu_percent:5.1f}% | "
                      f"RAM: {memory_mb:6.1f}MB | "
                      f"I/O: R{read_mb:.1f}/W{write_mb:.1f}MB | "
                      f"Threads: {threads}", end="", flush=True)
                
                time.sleep(1)
                
            except Exception:
                pass
        
        self.running = False
        self._print_report()
    
    def _print_report(self):
        """Print final benchmark report."""
        if not self.samples:
            print("\n\n❌ No samples collected")
            return
        
        cpu_values = [s["cpu_percent"] for s in self.samples]
        mem_values = [s["memory_mb"] for s in self.samples]
        
        cpu_avg = sum(cpu_values) / len(cpu_values)
        cpu_max = max(cpu_values)
        cpu_min = min(cpu_values)
        
        mem_avg = sum(mem_values) / len(mem_values)
        mem_max = max(mem_values)
        mem_min = min(mem_values)
        
        total_read = self.samples[-1]["read_mb"] if self.samples else 0
        total_write = self.samples[-1]["write_mb"] if self.samples else 0
        
        print(f"\n\n{'='*60}")
        print("📊 BENCHMARK RESULTS")
        print(f"{'='*60}")
        print(f"Duration: {len(self.samples)}s | Samples: {len(self.samples)}")
        print(f"{'─'*60}")
        print(f"{'METRIC':<20} {'AVG':>10} {'MIN':>10} {'MAX':>10}")
        print(f"{'─'*60}")
        print(f"{'CPU Usage (%)':<20} {cpu_avg:>9.1f}% {cpu_min:>9.1f}% {cpu_max:>9.1f}%")
        print(f"{'Memory (MB)':<20} {mem_avg:>10.1f} {mem_min:>10.1f} {mem_max:>10.1f}")
        print(f"{'─'*60}")
        print(f"{'Disk Read (MB)':<20} {total_read:>10.2f}")
        print(f"{'Disk Write (MB)':<20} {total_write:>10.2f}")
        print(f"{'─'*60}")
        
        if cpu_avg < 5:
            cpu_rating = "🟢 Excellent"
        elif cpu_avg < 15:
            cpu_rating = "🟡 Good"
        elif cpu_avg < 30:
            cpu_rating = "🟠 Moderate"
        else:
            cpu_rating = "🔴 High"
        
        if mem_avg < 50:
            mem_rating = "🟢 Excellent"
        elif mem_avg < 100:
            mem_rating = "🟡 Good"
        elif mem_avg < 200:
            mem_rating = "🟠 Moderate"
        else:
            mem_rating = "🔴 High"
        
        print(f"\n{'RATING':<20}")
        print(f"{'CPU':<20} {cpu_rating}")
        print(f"{'Memory':<20} {mem_rating}")
        print(f"{'='*60}\n")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)


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
    
    perf_monitor = None
    if args.benchmark:
        perf_monitor = PerformanceMonitor(duration=args.benchmark_duration)
        perf_monitor.start()
    
    daemon = LeattDaemon(
        enable_systray=not args.no_systray,
        enable_web=args.web or config.web_enabled,
    )
    
    def signal_handler(signum, frame):
        logger.info("Shutdown signal received")
        if perf_monitor:
            perf_monitor.stop()
        daemon.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        daemon.start()
        return 0
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        if perf_monitor:
            perf_monitor.stop()
        daemon.stop()
        return 0
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
