#!/usr/bin/env python3
import argparse
import csv
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import requests
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency 'requests'. Install with: python3 -m pip install requests"
    ) from exc

ROOT = Path('/Users/viniciusromualdo/swe/openrasp_lab/sqli_rasp_experiment')
NS = 'sqli'
GATEWAY_URL = 'http://127.0.0.1:18080'
GATEWAY_URL_FROM_ZAP = 'http://host.docker.internal:18080'
ZAP_PORT = 8090
ZAP_API = f'http://127.0.0.1:{ZAP_PORT}'
ZAP_CONTAINER = 'sqli-rasp-experiment-zap'

PROFILE_PATHS = {
    'rasp-on': ROOT / 'k8s/profiles/rasp-on',
    'rasp-off': ROOT / 'k8s/profiles/rasp-off',
}

DEFAULT_FACTORIAL_PROFILES = [
    'rasp-on',
    'rasp-off',
]

@dataclass
class RunResult:
    profile: str
    reg_status: int
    login_status: int
    safe_status: int
    safe_time: float
    sqli_status: int
    sqli_time: float
    detector: str
    zap_alerts_total: int
    zap_alerts_sqli: int
    zap_alerts_high: int
    zap_alerts_medium: int
    zap_requests_total: int


class Runner:
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime('%Y%m%d-%H%M%S')
        self.csv_path = out_dir / f'zap-v2-{stamp}.csv'
        self.trace_path = out_dir / f'zap-v2-{stamp}.trace.log'
        self.alerts_path = out_dir / f'zap-v2-{stamp}.alerts.json'
        self.pf_proc = None

    def run(self, cmd: List[str], check=True, capture=False) -> subprocess.CompletedProcess:
        if capture:
            return subprocess.run(cmd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return subprocess.run(cmd, check=check)

    def apply_profile(self, profile: str):
        self.run(['kubectl', 'apply', '-k', str(PROFILE_PATHS[profile])])
        self.run(['kubectl', '-n', NS, 'rollout', 'restart', 'deploy/webgoat', 'deploy/api-gateway'])
        self.run(['kubectl', '-n', NS, 'rollout', 'status', 'deploy/api-gateway', '--timeout=300s'])
        self.run(['kubectl', '-n', NS, 'rollout', 'status', 'deploy/webgoat', '--timeout=420s'])

    def start_gateway_pf(self):
        self.stop_gateway_pf()
        self.pf_proc = subprocess.Popen(
            ['kubectl', '-n', NS, 'port-forward', 'svc/api-gateway', '18080:8080'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        for _ in range(30):
            try:
                r = requests.get(f'{GATEWAY_URL}/webgoat/WebGoat/login', timeout=2)
                if r.status_code in (200, 302):
                    return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError('gateway port-forward failed')

    def stop_gateway_pf(self):
        if self.pf_proc and self.pf_proc.poll() is None:
            os.killpg(os.getpgid(self.pf_proc.pid), signal.SIGTERM)
            try:
                self.pf_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(self.pf_proc.pid), signal.SIGKILL)
        self.pf_proc = None

    def start_zap(self):
        self.stop_zap()
        last_err = None
        for _ in range(6):
            p = subprocess.run([
                'docker', 'run', '--rm', '-d', '--name', ZAP_CONTAINER,
                '-p', f'127.0.0.1:{ZAP_PORT}:8090',
                'ghcr.io/zaproxy/zaproxy:stable',
                'zap.sh', '-daemon', '-host', '0.0.0.0', '-port', '8090',
                '-config', 'api.disablekey=true',
                '-config', 'api.addrs.addr.name=.*',
                '-config', 'api.addrs.addr.regex=true'
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if p.returncode == 0:
                break
            last_err = p.stdout
            time.sleep(2)
            self.stop_zap()
        else:
            raise RuntimeError(f'failed to start zap container: {last_err}')
        for _ in range(180):
            try:
                r = requests.get(f'{ZAP_API}/JSON/core/view/version/', timeout=2)
                if r.ok and 'version' in r.text:
                    return
            except Exception:
                pass
            time.sleep(1)
        logs = subprocess.run(['docker', 'logs', ZAP_CONTAINER], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
        raise RuntimeError(f'zap did not start; container logs:\n{logs[-2000:]}')

    def stop_zap(self):
        subprocess.run(['docker', 'rm', '-f', ZAP_CONTAINER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def zap_get(self, path: str, params=None):
        url = f'{ZAP_API}{path}'
        r = requests.get(url, params=params or {}, timeout=30)
        r.raise_for_status()
        return r.json()

    def wait_status(self, kind: str, scan_id: str, timeout=600):
        started = time.time()
        while True:
            if kind == 'spider':
                status = int(self.zap_get('/JSON/spider/view/status/', {'scanId': scan_id})['status'])
            else:
                status = int(self.zap_get('/JSON/ascan/view/status/', {'scanId': scan_id})['status'])
            if status >= 100:
                return
            if time.time() - started > timeout:
                raise TimeoutError(f'{kind} timeout {scan_id}')
            time.sleep(2)

    def seed_and_probe_via_zap(self, label: str) -> Tuple[int, int, int, float, int, float, str]:
        sess = requests.Session()
        sess.proxies = {'http': f'http://127.0.0.1:{ZAP_PORT}', 'https': f'http://127.0.0.1:{ZAP_PORT}'}
        sess.verify = False
        user = f'zap{int(time.time())}'
        pwd = 'Codex123!'

        sess.get(f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/registration', timeout=20)
        reg = sess.post(f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/register.mvc', data={
            'username': user, 'password': pwd, 'matchingPassword': pwd, 'agree': 'agree'
        }, timeout=20, allow_redirects=False)
        login = sess.post(f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/login', data={'username': user, 'password': pwd}, timeout=20, allow_redirects=False)

        t0 = time.time()
        safe = sess.post(
            f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/SqlInjection/attack8',
            data={'name': 'Smith', 'auth_tan': '3SL99A'},
            timeout=20,
            allow_redirects=False,
        )
        safe_t = time.time() - t0

        t1 = time.time()
        sqli = sess.post(
            f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/SqlInjection/attack8',
            data={'name': "Smith' OR '1'='1' --", 'auth_tan': 'x'},
            timeout=20,
            allow_redirects=False,
        )
        sqli_t = time.time() - t1

        detector = 'none'
        hdr = {k.lower(): v for k, v in sqli.headers.items()}
        body = sqli.text or ''
        if 'x-protected-by' in hdr and 'openrasp' in hdr['x-protected-by'].lower():
            detector = 'rasp'
        elif sqli.status_code == 403 or 'modsecurity' in body.lower():
            detector = 'waf'

        with self.trace_path.open('a') as f:
            f.write(f'== {label} probe ==\n')
            f.write(f'reg={reg.status_code} login={login.status_code} safe={safe.status_code} {safe_t:.6f}s sqli={sqli.status_code} {sqli_t:.6f}s detector={detector}\n')
            f.write('sqli_headers:\n')
            for k, v in sqli.headers.items():
                f.write(f'{k}: {v}\n')
            f.write('---\n')

        return reg.status_code, login.status_code, safe.status_code, safe_t, sqli.status_code, sqli_t, detector

    def run_zap_scan(self, label: str) -> Dict[str, int]:
        base = f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/'
        spider_id = self.zap_get('/JSON/spider/action/scan/', {'url': base, 'maxChildren': '20'})['scan']
        self.wait_status('spider', spider_id, timeout=300)

        ascan_id = self.zap_get('/JSON/ascan/action/scan/', {'url': base, 'recurse': 'true', 'inScopeOnly': 'false'})['scan']
        self.wait_status('ascan', ascan_id, timeout=420)

        alerts = []
        start = 0
        while True:
            batch = self.zap_get('/JSON/core/view/alerts/', {'baseurl': base, 'start': str(start), 'count': '500'})['alerts']
            if not batch:
                break
            alerts.extend(batch)
            start += len(batch)

        sqli = [a for a in alerts if 'sql injection' in a.get('name', '').lower() or a.get('cweid') == '89']
        high = [a for a in alerts if a.get('risk') == 'High']
        medium = [a for a in alerts if a.get('risk') == 'Medium']
        msg_total = int(self.zap_get('/JSON/core/view/numberOfMessages/').get('numberOfMessages', 0))

        with self.trace_path.open('a') as f:
            f.write(f'== {label} zap ==\n')
            f.write(f'alerts_total={len(alerts)} alerts_sqli={len(sqli)} high={len(high)} medium={len(medium)} requests_total={msg_total}\n')
            for a in sqli[:5]:
                f.write(f"sqli_alert: {a.get('name')} risk={a.get('risk')} url={a.get('url')} param={a.get('param')}\n")
            f.write('---\n')

        return {
            'alerts_total': len(alerts),
            'alerts_sqli': len(sqli),
            'alerts_high': len(high),
            'alerts_medium': len(medium),
            'requests_total': msg_total,
            'alerts_sample': sqli[:5],
        }

    def current_env(self):
        waf = self.run(['kubectl', '-n', NS, 'get', 'deploy', 'api-gateway', '-o', "jsonpath={range .spec.template.spec.containers[?(@.name=='gateway')].env[?(@.name=='MODSEC_RULE_ENGINE')]}{.value}{end}"], capture=True).stdout.strip() or 'unknown'
        target = self.run(['kubectl', '-n', NS, 'get', 'svc', 'webgoat', '-o', 'jsonpath={.spec.ports[0].targetPort}'], capture=True).stdout.strip()
        jto = self.run(['kubectl', '-n', NS, 'get', 'deploy', 'webgoat', '-o', "jsonpath={range .spec.template.spec.containers[?(@.name=='webgoat')].env[*]}{.name}={.value}{'\\n'}{end}"], capture=True).stdout
        jto_state = 'image-default'
        for ln in jto.splitlines():
            if ln.startswith('JAVA_TOOL_OPTIONS='):
                jto_state = 'empty-override' if ln == 'JAVA_TOOL_OPTIONS=' else 'explicit-override'
        return waf, target, jto_state


def main():
    parser = argparse.ArgumentParser(description='SQLi RASP experiment (ZAP base library runner)')
    parser.add_argument('--profiles', default=','.join(DEFAULT_FACTORIAL_PROFILES), help='Comma separated profiles')
    args = parser.parse_args()
    profiles = [p.strip() for p in args.profiles.split(',') if p.strip()]

    for p in profiles:
        if p not in PROFILE_PATHS:
            raise SystemExit(f'Unknown profile: {p}')

    runner = Runner(ROOT / 'results')
    rows: List[RunResult] = []
    alerts_dump: Dict[str, dict] = {}

    try:
        for prof in profiles:
            runner.apply_profile(prof)
            runner.start_gateway_pf()
            runner.start_zap()
            reg, login, safe, safe_t, sqli, sqli_t, detector = runner.seed_and_probe_via_zap(prof)
            zap_stats = runner.run_zap_scan(prof)
            waf, webgoat_target, jto = runner.current_env()
            rows.append(RunResult(
                profile=prof,
                reg_status=reg,
                login_status=login,
                safe_status=safe,
                safe_time=safe_t,
                sqli_status=sqli,
                sqli_time=sqli_t,
                detector=detector,
                zap_alerts_total=zap_stats['alerts_total'],
                zap_alerts_sqli=zap_stats['alerts_sqli'],
                zap_alerts_high=zap_stats['alerts_high'],
                zap_alerts_medium=zap_stats['alerts_medium'],
                zap_requests_total=zap_stats['requests_total'],
            ))
            alerts_dump[prof] = {
                'waf_engine': waf,
                'webgoat_target_port': webgoat_target,
                'java_tool_options_state': jto,
                'alerts_sample': zap_stats['alerts_sample'],
            }
            runner.stop_zap()
            runner.stop_gateway_pf()

        with runner.csv_path.open('w', newline='') as f:
            w = csv.writer(f)
            w.writerow([
                'profile','reg_status','login_status','safe_status','safe_time_s',
                'sqli_status','sqli_time_s','detector',
                'zap_alerts_total','zap_alerts_sqli','zap_alerts_high','zap_alerts_medium','zap_requests_total'
            ])
            for r in rows:
                w.writerow([
                    r.profile,r.reg_status,r.login_status,r.safe_status,f'{r.safe_time:.6f}',
                    r.sqli_status,f'{r.sqli_time:.6f}',r.detector,
                    r.zap_alerts_total,r.zap_alerts_sqli,r.zap_alerts_high,r.zap_alerts_medium,r.zap_requests_total,
                ])

        with runner.alerts_path.open('w') as f:
            json.dump(alerts_dump, f, indent=2)

        print(f'CSV: {runner.csv_path}')
        print(f'TRACE: {runner.trace_path}')
        print(f'ALERTS: {runner.alerts_path}')

    finally:
        runner.stop_zap()
        runner.stop_gateway_pf()
        subprocess.run(['kubectl', 'apply', '-k', str(ROOT / 'k8s/profiles/rasp-on')], stdout=subprocess.DEVNULL)
        subprocess.run(['kubectl', '-n', NS, 'rollout', 'restart', 'deploy/webgoat', 'deploy/api-gateway'], stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
