#!/usr/bin/env python3
"""
Comprehensive Performance Testing Script
For Universal Bitcoin Identity Layer

Tests:
- Service availability
- Endpoint response times
- Resource usage (CPU, Memory)
- Database connectivity
- Redis connectivity
- Load testing
- Concurrent request handling
"""

import os
import sys
import time
import json
import requests
import psutil
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

class PerformanceTester:
    def __init__(self, base_url: str = "http://127.0.0.1:5000"):
        self.base_url = base_url
        self.results = []
        self.start_time = None

    def print_header(self, text: str):
        """Print formatted section header"""
        print(f"\n{'='*60}")
        print(f"  {text}")
        print(f"{'='*60}\n")

    def print_result(self, test_name: str, status: str, details: str = ""):
        """Print test result"""
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_icon} {test_name:<40} [{status}]")
        if details:
            print(f"   {details}")

    def check_process_running(self) -> Tuple[bool, str]:
        """Check if Flask/Gunicorn process is running"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'wsgi' in cmdline.lower() or ('python' in proc.info['name'].lower() and 'app' in cmdline):
                    return True, f"PID: {proc.info['pid']}, CMD: {cmdline[:50]}..."
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False, "No Flask/Gunicorn process found"

    def get_resource_usage(self) -> Dict:
        """Get system resource usage"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Find app process if running
        app_cpu = 0
        app_memory = 0
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'wsgi' in cmdline.lower() or ('python' in proc.info['name'].lower() and 'app' in cmdline):
                    app_cpu += proc.cpu_percent()
                    app_memory += proc.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_available_gb': memory.available / (1024**3),
            'disk_percent': disk.percent,
            'disk_free_gb': disk.free / (1024**3),
            'app_cpu': app_cpu,
            'app_memory': app_memory
        }

    def test_endpoint(self, endpoint: str, method: str = "GET", timeout: int = 10) -> Dict:
        """Test a single endpoint and measure response time"""
        url = f"{self.base_url}{endpoint}"
        try:
            start = time.time()
            response = requests.request(method, url, timeout=timeout, verify=False)
            elapsed = time.time() - start

            return {
                'endpoint': endpoint,
                'status_code': response.status_code,
                'response_time': elapsed,
                'success': 200 <= response.status_code < 400,
                'size': len(response.content)
            }
        except requests.exceptions.ConnectionError:
            return {
                'endpoint': endpoint,
                'error': 'Connection refused',
                'success': False
            }
        except requests.exceptions.Timeout:
            return {
                'endpoint': endpoint,
                'error': 'Request timeout',
                'success': False
            }
        except Exception as e:
            return {
                'endpoint': endpoint,
                'error': str(e),
                'success': False
            }

    def test_concurrent_requests(self, endpoint: str, num_requests: int = 50, workers: int = 10) -> Dict:
        """Test concurrent requests to an endpoint"""
        url = f"{self.base_url}{endpoint}"
        response_times = []
        errors = 0

        def make_request():
            try:
                start = time.time()
                response = requests.get(url, timeout=10, verify=False)
                elapsed = time.time() - start
                return {'success': 200 <= response.status_code < 400, 'time': elapsed}
            except:
                return {'success': False, 'time': 0}

        start_time = time.time()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(make_request) for _ in range(num_requests)]
            for future in as_completed(futures):
                result = future.result()
                if result['success']:
                    response_times.append(result['time'])
                else:
                    errors += 1

        total_time = time.time() - start_time

        if response_times:
            return {
                'total_requests': num_requests,
                'successful': len(response_times),
                'failed': errors,
                'total_time': total_time,
                'requests_per_second': num_requests / total_time,
                'avg_response_time': statistics.mean(response_times),
                'median_response_time': statistics.median(response_times),
                'min_response_time': min(response_times),
                'max_response_time': max(response_times),
                'p95_response_time': statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times)
            }
        else:
            return {
                'total_requests': num_requests,
                'successful': 0,
                'failed': errors,
                'error': 'All requests failed'
            }

    def check_database_connectivity(self) -> Tuple[bool, str]:
        """Check PostgreSQL connectivity"""
        try:
            import psycopg2
            from dotenv import load_dotenv
            load_dotenv()

            db_url = os.getenv('DATABASE_URL')
            if not db_url:
                return False, "DATABASE_URL not set"

            # Parse connection string
            conn = psycopg2.connect(db_url)
            cur = conn.cursor()
            cur.execute('SELECT version();')
            version = cur.fetchone()[0]
            cur.close()
            conn.close()
            return True, version
        except ImportError:
            return False, "psycopg2 not installed"
        except Exception as e:
            return False, str(e)

    def check_redis_connectivity(self) -> Tuple[bool, str]:
        """Check Redis connectivity"""
        try:
            import redis
            from dotenv import load_dotenv
            load_dotenv()

            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            r = redis.from_url(redis_url)
            r.ping()
            info = r.info()
            return True, f"Redis {info.get('redis_version', 'unknown')} - {info.get('used_memory_human', 'N/A')} used"
        except ImportError:
            return False, "redis package not installed"
        except Exception as e:
            return False, str(e)

    def run_all_tests(self):
        """Run all performance tests"""
        self.start_time = datetime.now()

        print("\n" + "="*60)
        print("  UNIVERSAL BITCOIN IDENTITY LAYER")
        print("  Performance & Health Check Report")
        print("  " + self.start_time.strftime("%Y-%m-%d %H:%M:%S"))
        print("="*60)

        # Test 1: Process Check
        self.print_header("1. Process Status")
        is_running, proc_info = self.check_process_running()
        if is_running:
            self.print_result("Flask/Gunicorn Process", "PASS", proc_info)
        else:
            self.print_result("Flask/Gunicorn Process", "FAIL", proc_info)
            print("\n⚠️  WARNING: Application is not running!")
            print("   Start it with: python3 wsgi.py")
            print("   Or with gunicorn: gunicorn -w 4 -b 127.0.0.1:5000 wsgi:application")

        # Test 2: Resource Usage
        self.print_header("2. System Resources")
        resources = self.get_resource_usage()
        self.print_result("CPU Usage", "PASS" if resources['cpu_percent'] < 80 else "WARN",
                         f"{resources['cpu_percent']:.1f}% (App: {resources['app_cpu']:.1f}%)")
        self.print_result("Memory Usage", "PASS" if resources['memory_percent'] < 80 else "WARN",
                         f"{resources['memory_percent']:.1f}% (App: {resources['app_memory']:.1f}%, Available: {resources['memory_available_gb']:.2f} GB)")
        self.print_result("Disk Usage", "PASS" if resources['disk_percent'] < 90 else "WARN",
                         f"{resources['disk_percent']:.1f}% (Free: {resources['disk_free_gb']:.2f} GB)")

        # Test 3: Database & Redis
        self.print_header("3. Backend Services")
        db_ok, db_msg = self.check_database_connectivity()
        self.print_result("PostgreSQL Connection", "PASS" if db_ok else "FAIL", db_msg)

        redis_ok, redis_msg = self.check_redis_connectivity()
        self.print_result("Redis Connection", "PASS" if redis_ok else "FAIL", redis_msg)

        # Test 4: Endpoint Availability
        self.print_header("4. Endpoint Availability & Response Times")
        endpoints = [
            '/health',
            '/.well-known/openid-configuration',
            '/metrics/prometheus',
            '/oauth/authorize',
            '/lnurl/auth'
        ]

        endpoint_results = []
        for endpoint in endpoints:
            result = self.test_endpoint(endpoint)
            endpoint_results.append(result)

            if result.get('success'):
                self.print_result(
                    f"{endpoint}",
                    "PASS",
                    f"Status: {result['status_code']}, Time: {result['response_time']*1000:.0f}ms, Size: {result['size']} bytes"
                )
            else:
                self.print_result(
                    f"{endpoint}",
                    "FAIL",
                    result.get('error', 'Unknown error')
                )

        # Test 5: Load Testing (only if service is available)
        if any(r.get('success') for r in endpoint_results):
            self.print_header("5. Load Testing (Concurrent Requests)")

            # Test with different concurrency levels
            for num_requests, workers in [(50, 10), (100, 20)]:
                print(f"\nTesting {num_requests} requests with {workers} concurrent workers...")
                load_result = self.test_concurrent_requests('/health', num_requests, workers)

                if 'error' not in load_result:
                    print(f"  ✅ Completed: {load_result['successful']}/{load_result['total_requests']} successful")
                    print(f"     Throughput: {load_result['requests_per_second']:.2f} req/sec")
                    print(f"     Avg Response: {load_result['avg_response_time']*1000:.0f}ms")
                    print(f"     Median Response: {load_result['median_response_time']*1000:.0f}ms")
                    print(f"     P95 Response: {load_result['p95_response_time']*1000:.0f}ms")
                    print(f"     Min/Max: {load_result['min_response_time']*1000:.0f}ms / {load_result['max_response_time']*1000:.0f}ms")
                else:
                    print(f"  ❌ Load test failed: {load_result['error']}")

        # Summary
        self.print_header("Summary")

        total_tests = len(endpoint_results) + 4  # endpoints + process + db + redis + resources
        passed = sum(1 for r in endpoint_results if r.get('success', False))
        passed += (1 if is_running else 0)
        passed += (1 if db_ok else 0)
        passed += (1 if redis_ok else 0)
        passed += 1  # resources always pass

        print(f"Tests Passed: {passed}/{total_tests}")
        print(f"Overall Health: {'✅ HEALTHY' if passed >= total_tests * 0.8 else '⚠️  DEGRADED' if passed >= total_tests * 0.5 else '❌ CRITICAL'}")
        print(f"\nTest Duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds")
        print("\n" + "="*60 + "\n")

        # Recommendations
        if not is_running:
            print("📌 RECOMMENDATION: Start the application service")
        if not db_ok:
            print("📌 RECOMMENDATION: Check PostgreSQL configuration and connectivity")
        if not redis_ok:
            print("📌 RECOMMENDATION: Check Redis configuration and connectivity")
        if resources['cpu_percent'] > 80:
            print("📌 RECOMMENDATION: High CPU usage detected, consider scaling")
        if resources['memory_percent'] > 80:
            print("📌 RECOMMENDATION: High memory usage detected, check for memory leaks")

        print("")

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    # Allow custom base URL
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"

    tester = PerformanceTester(base_url)
    tester.run_all_tests()
