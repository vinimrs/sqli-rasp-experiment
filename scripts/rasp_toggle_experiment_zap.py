#!/usr/bin/env python3
import argparse
import csv
import html
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from rasp_toggle_experiment_zap_lib import (
    DEFAULT_FACTORIAL_PROFILES,
    GATEWAY_URL_FROM_ZAP,
    NS,
    PROFILE_PATHS,
    ROOT,
    Runner as RunnerV2,
)


SQLI_MARKERS = [
    "' or '1'='1",
    "%27%20or%20%271%27%3d%271",
    " or 'x'='x",
    "') or ('1'='1",
    " union select ",
    " union all select ",
    "sleep(",
    "benchmark(",
    "waitfor delay",
    " or 1=1",
    " and 1=1",
    " and 1=2",
    "information_schema",
    "xp_cmdshell",
    " --",
]

SQLI_PATTERNS = [
    ('union_based', re.compile(r'\bunion\s+(?:all\s+)?select\b'), 'union select', 4),
    ('time_based', re.compile(r'\b(?:sleep|benchmark)\s*\(|\bwaitfor\s+delay\b'), 'time delay function', 3),
    ('metadata_probe', re.compile(r'\binformation_schema\b|\bsysobjects\b|\bsys\.tables\b'), 'metadata table probe', 3),
    ('boolean_based', re.compile(r"(?:'|\")?\s+(?:or|and)\s+(?:'?\w+'?\s*=\s*'?\w+'?|\d+\s*=\s*\d+)"), 'boolean predicate', 3),
    ('stacked_query', re.compile(r';\s*(?:select|insert|update|delete|drop|waitfor|exec)\b'), 'stacked query', 3),
    ('comment_termination', re.compile(r"(?:--|#|/\*)"), 'sql comment delimiter', 2),
    ('error_based', re.compile(r'\b(?:extractvalue|updatexml|concat\s*\(|cast\s*\(|convert\s*\()\b'), 'error based function', 2),
    ('command_execution', re.compile(r'\bxp_cmdshell\b'), 'command execution procedure', 4),
]

WAF_HEADER_MARKERS = [
    'x-mod-security',
    'x-modsec',
    'x-waf',
]

WAF_BODY_MARKERS = [
    'modsecurity',
    'owasp crs',
    'coraza',
    'access denied with code',
    'request denied by modsecurity',
    'modsecurity action',
]

WAF_RULE_REGEX = re.compile(r'\b9(?:2|3|4)\d{3}\b')
MAX_CAPTURE = 300
DEFAULT_SCAN_PATHS = [
    '/webgoat/WebGoat/SqlInjection',
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
    zap_blocked_total: int
    zap_blocked_waf: int
    zap_blocked_rasp: int
    zap_sqli_like_total: int
    zap_sqli_like_blocked: int


class Runner(RunnerV2):
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime('%Y%m%d-%H%M%S')
        self.csv_path = out_dir / f'zap-{stamp}.csv'
        self.trace_path = out_dir / f'zap-{stamp}.trace.log'
        self.alerts_path = out_dir / f'zap-{stamp}.alerts.json'
        self.all_alerts_path = out_dir / f'zap-{stamp}.zap-alerts.json'
        self.requests_csv_path = out_dir / f'zap-{stamp}.requests.csv'
        self.pf_proc = None
        self.message_rows: List[dict] = []
        self.all_alerts: Dict[str, List[dict]] = {}

    def log_event(self, message: str):
        line = f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] {message}'
        print(line, flush=True)
        with self.trace_path.open('a') as f:
            f.write(f'event: {line}\n')

    def webgoat_pod_snapshot(self) -> List[dict]:
        out = self.run(
            ['kubectl', '-n', NS, 'get', 'pods', '-l', 'app=webgoat', '-o', 'json'],
            capture=True,
        ).stdout
        data = json.loads(out)
        pods = []
        for item in data.get('items', []):
            statuses = item.get('status', {}).get('containerStatuses') or []
            ready_count = sum(1 for st in statuses if st.get('ready'))
            restart_count = sum(int(st.get('restartCount', 0)) for st in statuses)
            pods.append({
                'name': item.get('metadata', {}).get('name', ''),
                'phase': item.get('status', {}).get('phase', ''),
                'ready': f'{ready_count}/{len(statuses)}',
                'restarts': restart_count,
                'created': item.get('metadata', {}).get('creationTimestamp', ''),
            })
        return pods

    def wait_single_ready_webgoat(self, timeout: int = 120):
        deadline = time.time() + timeout
        while True:
            pods = self.webgoat_pod_snapshot()
            running = [p for p in pods if p['phase'] == 'Running']
            ready = [p for p in pods if p['phase'] == 'Running' and p['ready'].startswith('2/2')]
            self.log_event(
                f"WEBGOAT_PODS count={len(pods)} running={len(running)} ready={len(ready)} names={','.join(p['name'] for p in pods)}"
            )
            if len(ready) == 1:
                return
            if time.time() >= deadline:
                summary = '; '.join(
                    f"{p['name']} phase={p['phase']} ready={p['ready']} restarts={p['restarts']}" for p in pods
                )
                raise RuntimeError(
                    f'Expected exactly 1 ready webgoat pod before scan; got {len(ready)} after {timeout}s. pods={summary}'
                )
            time.sleep(3)

    def openrasp_runtime_health(self) -> Dict[str, str]:
        logs = self.run(
            ['kubectl', '-n', NS, 'logs', 'deploy/webgoat', '-c', 'webgoat', '--tail=400'],
            capture=True,
        ).stdout.lower()
        if 'failed to load native library' in logs or 'couldn\'t load library openrasp_v8_java' in logs:
            return {'status': 'error', 'evidence': 'openrasp-native-load-failed'}
        if 'javaagent:/opt/rasp/rasp.jar' in logs and 'picked up java_tool_options' in logs:
            return {'status': 'loaded', 'evidence': 'javaagent-detected'}
        return {'status': 'unknown', 'evidence': 'no-openrasp-signature'}

    def current_message_count(self) -> int:
        return int(self.zap_get('/JSON/core/view/numberOfMessages/').get('numberOfMessages', 0))

    def classify_response(self, status: int, response_header: str, response_body: str) -> Dict[str, str]:
        hdr = (response_header or '').lower()
        body = (response_body or '').lower()
        rasp_header = 'x-protected-by: openrasp' in hdr
        rasp_redirect = 'location: https://rasp.baidu.com/blocked/' in hdr or 'location: https://rasp.baidu.com/blocked2/' in hdr
        if status in (301, 302, 303, 307, 308, 403) and rasp_redirect:
            return {'layer': 'rasp', 'evidence': 'openrasp-block'}
        if status in (301, 302, 303, 307, 308) and ('rasp.baidu.com/blocked' in body or 'rasp.baidu.com/blocked2' in body):
            return {'layer': 'rasp', 'evidence': 'openrasp-body-redirect'}
        if rasp_header:
            return {'layer': 'none', 'evidence': 'openrasp-header-only'}
        waf_hdr_match = next((m for m in WAF_HEADER_MARKERS if m in hdr), '')
        if waf_hdr_match:
            return {'layer': 'waf', 'evidence': f'waf-header:{waf_hdr_match}'}
        waf_body_match = next((m for m in WAF_BODY_MARKERS if m in body), '')
        if waf_body_match:
            return {'layer': 'waf', 'evidence': f'waf-body:{waf_body_match}'}
        waf_rule_match = WAF_RULE_REGEX.search(body) or WAF_RULE_REGEX.search(hdr)
        if waf_rule_match:
            return {'layer': 'waf', 'evidence': f'waf-rule-id:{waf_rule_match.group(0)}'}
        if status in (403, 406):
            return {'layer': 'none', 'evidence': f'http-{status}-no-waf-signature'}
        return {'layer': 'none', 'evidence': 'application-response'}

    def parse_request(self, request_header: str) -> Dict[str, str]:
        first = ''
        if request_header:
            first = request_header.splitlines()[0].strip()
        parts = first.split()
        method = parts[0] if len(parts) >= 1 else ''
        url = parts[1] if len(parts) >= 2 else ''
        return {'method': method, 'url': url}

    def parse_status(self, response_header: str) -> int:
        if not response_header:
            return 0
        first = response_header.splitlines()[0].strip()
        m = re.search(r'\s(\d{3})(?:\s|$)', first)
        return int(m.group(1)) if m else 0

    def detect_sqli_marker(self, url: str, request_body: str) -> str:
        analysis = self.analyze_sqli_payload(url, request_body)
        return analysis['marker']

    def normalize_payload(self, value: str) -> str:
        normalized = value or ''
        for _ in range(3):
            decoded = html.unescape(unquote_plus(normalized))
            if decoded == normalized:
                break
            normalized = decoded
        normalized = normalized.replace('\x00', '')
        normalized = re.sub(r'/\*.*?\*/', ' ', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip().lower()
        return normalized

    def request_parameter_values(self, url: str, request_body: str) -> List[Dict[str, str]]:
        parsed = urlsplit(url)
        values = []
        for source, pairs in (
            ('query', parse_qsl(parsed.query, keep_blank_values=True)),
            ('body', parse_qsl(request_body or '', keep_blank_values=True)),
        ):
            for name, value in pairs:
                values.append({
                    'source': source,
                    'param': name,
                    'raw': value,
                    'normalized': self.normalize_payload(value),
                })
        if not values:
            values.append({
                'source': 'url',
                'param': '',
                'raw': url,
                'normalized': self.normalize_payload(url),
            })
        return values

    def analyze_sqli_payload(self, url: str, request_body: str) -> Dict[str, object]:
        best = {
            'is_sqli_like': False,
            'marker': '',
            'pattern_type': '',
            'score': 0,
            'evidence': '',
        }
        for item in self.request_parameter_values(url, request_body):
            haystack = item['normalized']
            for pattern_type, regex, marker_label, score in SQLI_PATTERNS:
                match = regex.search(haystack)
                if match and score > best['score']:
                    best = {
                        'is_sqli_like': True,
                        'marker': match.group(0),
                        'pattern_type': pattern_type,
                        'score': score,
                        'evidence': f"source={item['source']},param={item['param']},type={pattern_type},marker={marker_label}",
                    }
            for marker in SQLI_MARKERS:
                normalized_marker = self.normalize_payload(marker)
                if normalized_marker and normalized_marker in haystack and best['score'] < 2:
                    best = {
                        'is_sqli_like': True,
                        'marker': marker,
                        'pattern_type': 'marker_match',
                        'score': 2,
                        'evidence': f"source={item['source']},param={item['param']},type=marker_match,marker={marker}",
                    }
        return best

    def request_params_summary(self, url: str, request_body: str) -> str:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True) + parse_qsl(request_body or '', keep_blank_values=True)
        if not pairs:
            return ''
        return '&'.join(f'{k}={unquote_plus(v)}' for k, v in pairs)[:MAX_CAPTURE]

    def text_excerpt(self, value: str) -> str:
        compact = re.sub(r'\s+', ' ', unquote_plus(value or '').replace('\x00', '')).strip()
        return compact[:MAX_CAPTURE]

    def fetch_message_rows(self, profile: str, seed_count: int) -> Dict[str, int]:
        base = f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/'
        rows = []
        start = 0
        while True:
            batch = self.zap_get('/JSON/core/view/messages/', {'baseurl': base, 'start': str(start), 'count': '500'}).get('messages', [])
            if not batch:
                break
            rows.extend(batch)
            start += len(batch)

        blocked_total = 0
        blocked_waf = 0
        blocked_rasp = 0
        sqli_like_total = 0
        sqli_like_blocked = 0

        for idx, msg in enumerate(rows, start=1):
            request_header = msg.get('requestHeader', '')
            request_body = msg.get('requestBody', '')
            response_header = msg.get('responseHeader', '')
            response_body = msg.get('responseBody', '')
            parsed = self.parse_request(request_header)
            status = self.parse_status(response_header)
            sqli_analysis = self.analyze_sqli_payload(parsed['url'], request_body)
            marker = str(sqli_analysis['marker'])
            is_sqli_like = bool(sqli_analysis['is_sqli_like'])
            classified = self.classify_response(status, response_header, response_body)
            phase = 'seed' if idx <= seed_count else 'scan'

            if classified['layer'] != 'none':
                blocked_total += 1
                if classified['layer'] == 'waf':
                    blocked_waf += 1
                elif classified['layer'] == 'rasp':
                    blocked_rasp += 1
            if is_sqli_like:
                sqli_like_total += 1
                if classified['layer'] != 'none':
                    sqli_like_blocked += 1

            self.message_rows.append({
                'profile': profile,
                'phase': phase,
                'message_seq': idx,
                'message_id': msg.get('id', ''),
                'method': parsed['method'],
                'url': parsed['url'],
                'status_code': status,
                'layer': classified['layer'],
                'evidence': classified['evidence'],
                'is_sqli_like': '1' if is_sqli_like else '0',
                'sqli_marker': marker,
                'sqli_pattern_type': sqli_analysis['pattern_type'],
                'sqli_score': sqli_analysis['score'],
                'sqli_evidence': sqli_analysis['evidence'],
                'request_params': self.request_params_summary(parsed['url'], request_body),
                'request_body_decoded': self.text_excerpt(request_body),
                'response_excerpt': self.text_excerpt(response_body),
                'request_size': len(request_body or ''),
                'response_size': len(response_body or ''),
            })

        return {
            'blocked_total': blocked_total,
            'blocked_waf': blocked_waf,
            'blocked_rasp': blocked_rasp,
            'sqli_like_total': sqli_like_total,
            'sqli_like_blocked': sqli_like_blocked,
        }

    def run_zap_scan(
        self,
        label: str,
        seed_count: int,
        spider_timeout: int = 300,
        ascan_timeout: int = 900,
        scan_base_url: str = f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/',
        scan_paths: List[str] = None,
        spider_max_children: int = 10,
        disable_spider: bool = False,
    ) -> Dict[str, int]:
        base = scan_base_url.rstrip('/') + '/'
        ascan_targets = []
        if scan_paths:
            for raw_path in scan_paths:
                path = raw_path.strip()
                if not path:
                    continue
                if path.startswith('/'):
                    ascan_targets.append(f'{GATEWAY_URL_FROM_ZAP}{path}')
                else:
                    ascan_targets.append(path)
        else:
            ascan_targets.append(base)

        spider_target = ascan_targets[0] if scan_paths else base
        if not disable_spider:
            spider_id = self.zap_get('/JSON/spider/action/scan/', {'url': spider_target, 'maxChildren': str(spider_max_children)})['scan']
            self.wait_status('spider', spider_id, timeout=spider_timeout)

        for target in ascan_targets:
            ascan_id = self.zap_get('/JSON/ascan/action/scan/', {'url': target, 'recurse': 'true', 'inScopeOnly': 'false'})['scan']
            self.wait_status('ascan', ascan_id, timeout=ascan_timeout)

        alerts = []
        start = 0
        while True:
            batch = self.zap_get('/JSON/core/view/alerts/', {'baseurl': base, 'start': str(start), 'count': '500'})['alerts']
            if not batch:
                break
            alerts.extend(batch)
            start += len(batch)
        self.all_alerts[label] = alerts

        sqli = [a for a in alerts if 'sql injection' in a.get('name', '').lower() or a.get('cweid') == '89']
        high = [a for a in alerts if a.get('risk') == 'High']
        medium = [a for a in alerts if a.get('risk') == 'Medium']
        msg_total = self.current_message_count()
        msg_stats = self.fetch_message_rows(label, seed_count)

        with self.trace_path.open('a') as f:
            f.write(f'== {label} zap ==\n')
            f.write(f'spider_target={spider_target} ascan_targets={",".join(ascan_targets)}\n')
            f.write(
                'alerts_total={0} alerts_sqli={1} high={2} medium={3} requests_total={4} blocked_total={5} blocked_waf={6} blocked_rasp={7} sqli_like_total={8} sqli_like_blocked={9}\n'.format(
                    len(alerts),
                    len(sqli),
                    len(high),
                    len(medium),
                    msg_total,
                    msg_stats['blocked_total'],
                    msg_stats['blocked_waf'],
                    msg_stats['blocked_rasp'],
                    msg_stats['sqli_like_total'],
                    msg_stats['sqli_like_blocked'],
                )
            )
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
            **msg_stats,
        }

    def write_message_csv(self):
        with self.requests_csv_path.open('w', newline='') as f:
            w = csv.writer(f)
            w.writerow([
                'profile',
                'phase',
                'message_seq',
                'message_id',
                'method',
                'url',
                'status_code',
                'layer',
                'evidence',
                'is_sqli_like',
                'sqli_marker',
                'sqli_pattern_type',
                'sqli_score',
                'sqli_evidence',
                'request_params',
                'request_body_decoded',
                'response_excerpt',
                'request_size',
                'response_size',
            ])
            for row in self.message_rows:
                w.writerow([
                    row['profile'],
                    row['phase'],
                    row['message_seq'],
                    row['message_id'],
                    row['method'],
                    row['url'],
                    row['status_code'],
                    row['layer'],
                    row['evidence'],
                    row['is_sqli_like'],
                    row['sqli_marker'],
                    row['sqli_pattern_type'],
                    row['sqli_score'],
                    row['sqli_evidence'],
                    row['request_params'],
                    row['request_body_decoded'],
                    row['response_excerpt'],
                    row['request_size'],
                    row['response_size'],
                ])


def main():
    parser = argparse.ArgumentParser(description='SQLi RASP-ON/OFF experiment with ZAP per-request layer classification')
    parser.add_argument('--profiles', default=','.join(DEFAULT_FACTORIAL_PROFILES), help='Comma separated profiles')
    parser.add_argument(
        '--skip-profile-apply',
        action='store_true',
        help='Run against the currently deployed cluster state without kubectl apply or rollout restart before scanning',
    )
    parser.add_argument(
        '--skip-final-restore',
        action='store_true',
        help='Do not restore rasp-on or restart deployments in the cleanup block',
    )
    parser.add_argument(
        '--spider-timeout',
        type=int,
        default=300,
        help='Timeout in seconds for ZAP spider completion (default: 300)',
    )
    parser.add_argument(
        '--ascan-timeout',
        type=int,
        default=900,
        help='Timeout in seconds for ZAP active scan completion (default: 900)',
    )
    parser.add_argument(
        '--scan-base-url',
        default=f'{GATEWAY_URL_FROM_ZAP}/webgoat/WebGoat/',
        help='Base URL used by spider and alert collection (default: WebGoat root)',
    )
    parser.add_argument(
        '--scan-paths',
        default=','.join(DEFAULT_SCAN_PATHS),
        help='Comma-separated focused active-scan paths (absolute paths or full URLs)',
    )
    parser.add_argument(
        '--spider-max-children',
        type=int,
        default=10,
        help='Spider max children in focused mode (default: 10)',
    )
    parser.add_argument(
        '--disable-spider',
        action='store_true',
        help='Skip spider and run only active scans on --scan-paths',
    )
    args = parser.parse_args()
    profiles = [p.strip() for p in args.profiles.split(',') if p.strip()]
    scan_paths = [p.strip() for p in args.scan_paths.split(',') if p.strip()]

    if args.skip_profile_apply and len(profiles) != 1:
        raise SystemExit('--skip-profile-apply requires exactly one profile label, for example: --profiles current')

    if not args.skip_profile_apply:
        for p in profiles:
            if p not in PROFILE_PATHS:
                raise SystemExit(f'Unknown profile: {p}')

    runner = Runner(ROOT / 'results')
    rows: List[RunResult] = []
    alerts_dump: Dict[str, dict] = {}

    try:
        for prof in profiles:
            profile_label = prof.upper().replace('-', '_')
            runner.log_event(f'START_PROFILE {profile_label}')
            if not args.skip_profile_apply:
                runner.log_event(f'APPLY_PROFILE {profile_label}')
                runner.apply_profile(prof)
                runner.log_event(f'PROFILE_READY {profile_label}')
            else:
                runner.log_event(f'USING_CURRENT_CLUSTER_STATE profile={prof}')
            runner.wait_single_ready_webgoat()
            rasp_health = runner.openrasp_runtime_health()
            runner.log_event(f"OPENRASP_RUNTIME {profile_label} status={rasp_health['status']} evidence={rasp_health['evidence']}")
            runner.start_gateway_pf()
            runner.log_event(f'START_ZAP {profile_label}')
            runner.start_zap()
            runner.log_event(f'ZAP_READY {profile_label}')
            reg, login, safe, safe_t, sqli, sqli_t, detector = runner.seed_and_probe_via_zap(prof)
            runner.log_event(f'ZAP_SEED_DONE {profile_label}')
            seed_count = runner.current_message_count()
            runner.log_event(f'ZAP_SCAN_START {profile_label}')
            zap_stats = runner.run_zap_scan(
                prof,
                seed_count,
                spider_timeout=args.spider_timeout,
                ascan_timeout=args.ascan_timeout,
                scan_base_url=args.scan_base_url,
                scan_paths=scan_paths,
                spider_max_children=args.spider_max_children,
                disable_spider=args.disable_spider,
            )
            runner.log_event(f'ZAP_SCAN_DONE {profile_label}')
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
                zap_blocked_total=zap_stats['blocked_total'],
                zap_blocked_waf=zap_stats['blocked_waf'],
                zap_blocked_rasp=zap_stats['blocked_rasp'],
                zap_sqli_like_total=zap_stats['sqli_like_total'],
                zap_sqli_like_blocked=zap_stats['sqli_like_blocked'],
            ))
            alerts_dump[prof] = {
                'waf_engine': waf,
                'webgoat_target_port': webgoat_target,
                'java_tool_options_state': jto,
                'openrasp_runtime': rasp_health,
                'alerts_sample': zap_stats['alerts_sample'],
                'blocked_total': zap_stats['blocked_total'],
                'blocked_waf': zap_stats['blocked_waf'],
                'blocked_rasp': zap_stats['blocked_rasp'],
                'sqli_like_total': zap_stats['sqli_like_total'],
                'sqli_like_blocked': zap_stats['sqli_like_blocked'],
            }
            runner.stop_zap()
            runner.stop_gateway_pf()

        with runner.csv_path.open('w', newline='') as f:
            w = csv.writer(f)
            w.writerow([
                'profile',
                'reg_status',
                'login_status',
                'safe_status',
                'safe_time_s',
                'sqli_status',
                'sqli_time_s',
                'detector',
                'zap_alerts_total',
                'zap_alerts_sqli',
                'zap_alerts_high',
                'zap_alerts_medium',
                'zap_requests_total',
                'zap_blocked_total',
                'zap_blocked_waf',
                'zap_blocked_rasp',
                'zap_sqli_like_total',
                'zap_sqli_like_blocked',
            ])
            for r in rows:
                w.writerow([
                    r.profile,
                    r.reg_status,
                    r.login_status,
                    r.safe_status,
                    f'{r.safe_time:.6f}',
                    r.sqli_status,
                    f'{r.sqli_time:.6f}',
                    r.detector,
                    r.zap_alerts_total,
                    r.zap_alerts_sqli,
                    r.zap_alerts_high,
                    r.zap_alerts_medium,
                    r.zap_requests_total,
                    r.zap_blocked_total,
                    r.zap_blocked_waf,
                    r.zap_blocked_rasp,
                    r.zap_sqli_like_total,
                    r.zap_sqli_like_blocked,
                ])

        runner.write_message_csv()

        with runner.alerts_path.open('w') as f:
            json.dump(alerts_dump, f, indent=2)

        with runner.all_alerts_path.open('w') as f:
            json.dump(runner.all_alerts, f, indent=2)

        print(f'CSV: {runner.csv_path}')
        print(f'TRACE: {runner.trace_path}')
        print(f'ALERTS: {runner.alerts_path}')
        print(f'ZAP_ALERTS: {runner.all_alerts_path}')
        print(f'REQUESTS_CSV: {runner.requests_csv_path}')

    finally:
        runner.stop_zap()
        runner.stop_gateway_pf()
        if not args.skip_final_restore:
            runner.run(['kubectl', 'apply', '-k', str(ROOT / 'k8s/profiles/rasp-on')], check=False)
            runner.run(['kubectl', '-n', NS, 'rollout', 'restart', 'deploy/webgoat', 'deploy/api-gateway'], check=False)


if __name__ == '__main__':
    main()
