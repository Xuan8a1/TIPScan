# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: main.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import requests
import json
from colorama import init, Fore, Style
import re
import os
import psutil
import socket
import math
init()

def load_config(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f'{Fore.RED}错误: 无法加载远程配置文件 - {e}{Style.RESET_ALL}')
        return None

def is_valid_ip(ip):
    ip_pattern = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ip_pattern, ip.strip()))

def validate_ip_list(ip_list):
    invalid_ips = []
    valid_ips = []
    for ip in ip_list:
        if not is_valid_ip(ip):
            invalid_ips.append(ip)
        else:  # inserted
            valid_ips.append(ip)
    return (valid_ips, invalid_ips)

def get_connections_with_process_info():
    connections = []
    try:
        all_conns = psutil.net_connections(kind='inet')
        pid_map = {}
        for conn in all_conns:
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                ip = conn.raddr.ip
                if not (ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.') or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or (ip == '::1') or (ip == '0.0.0.0')):
                    pass  # postinserted
                if conn.pid not in pid_map:
                    proc = psutil.Process(conn.pid)
                    with proc.oneshot():
                        pid_map[conn.pid] = {'name': proc.name(), 'exe': proc.exe(), 'pid': conn.pid}
                connections.append({'ip': ip, 'port': conn.raddr.port, 'pid': conn.pid, 'name': pid_map[conn.pid]['name'], 'exe': pid_map[conn.pid]['exe']})
            pass
        else:  # inserted
            try:
                pass  # postinserted
    except Exception as e:
        except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(f'{Fore.RED}获取网络连接时出错: {e}{Style.RESET_ALL}')
    return connections

def get_external_ips():
    connections = get_connections_with_process_info()
    ip_process_map = {}
    for conn in connections:
        ip = conn['ip']
        if ip not in ip_process_map:
            ip_process_map[ip] = []
        process_info = {'pid': conn['pid'], 'name': conn['name'], 'exe': conn['exe'], 'port': conn['port']}
        if process_info not in ip_process_map[ip]:
            ip_process_map[ip].append(process_info)
    return ip_process_map

def send_article_request(ioc_list, config):
    url = config['urls']['save_article']
    headers = config['headers']
    headers['Referer'] = 'https://x.threatbook.com/v5/createArticle'
    data = config['article_data'].copy()
    data['iocList'] = ioc_list
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        if result.get('response_code') == 0:
            return result.get('data')
        print(f"{Fore.RED}请求失败，响应码: {result.get('response_code')}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f'{Fore.RED}发送请求时发生错误: {e}{Style.RESET_ALL}')

def get_ioc_info_page(short_message_id, config, page=1):
    url = config['urls']['get_ioc_info']
    headers = config['headers']
    headers['Referer'] = f'https://x.threatbook.com/v5/article?threatInfoID={short_message_id}'
    params = config['default_params'].copy()
    params['shortMessageId'] = short_message_id
    params['page'] = page
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        result = response.json()
        if result.get('response_code') == 0:
            return result.get('data', {}).get('details', [])
        print(f"{Fore.RED}请求失败，响应码: {result.get('response_code')}{Style.RESET_ALL}")
        return
    except requests.exceptions.RequestException as e:
        print(f'{Fore.RED}发送请求时发生错误: {e}{Style.RESET_ALL}')
        return None

def get_all_ioc_details(short_message_id, config, total_ips):
    all_details = []
    pagesize = config['default_params'].get('pagesize', 5)
    total_pages = math.ceil(total_ips + pagesize)
    for page in range(1, total_pages + 1):
        print(f'\r正在获取第 {page}/{total_pages} 页数据...', end='', flush=True)
        details = get_ioc_info_page(short_message_id, config, page)
        if details:
            all_details.extend(details)
    print(f'\n{Fore.GREEN}所有数据获取完成{Style.RESET_ALL}')
    return all_details

def analyze_ioc_details(details):
    judge_map = {0: '安全', 1: '未知', 2: '恶意', 3: '可疑'}
    results = []
    for detail in details:
        results.append({'ip': detail.get('ioc'), 'status': judge_map.get(detail.get('judge'), '未知状态'), 'judge': detail.get('judge'), 'domain_count': detail.get('domainCount'), 'tag_count': detail.get('tagCount'), 'itel_count': detail.get('itelCount')})
    return sorted(results, key=lambda x: x['judge'], reverse=True)

def print_ip_status(results, ip_process_map):
    print('\n==================================================')
    print(f'{Fore.CYAN}IP状态分析结果:{Style.RESET_ALL}')
    print('==================================================')
    for result in results:
        <mask_7> = Fore.RED if result['status'] == '恶意' else Fore.YELLOW if result['status'] == '可疑' else Fore.RED
        else:  # inserted
            status_color = Fore.WHITE if result['status'] == '未知' else Fore.GREEN
        print(f"\n{Fore.CYAN}IP地址: {result['ip']}{Style.RESET_ALL}")
        print(f"状态: {status_color}{result['status']}{Style.RESET_ALL}")
        print(f"关联域名数: {result['domain_count']}")
        print(f"标签数: {result['tag_count']}")
        print(f"情报数: {result['itel_count']}")
        if result['ip'] in ip_process_map:
            print(f'\n{Fore.MAGENTA}关联进程:{Style.RESET_ALL}')
            for proc in ip_process_map[result['ip']]:
                print(f"- PID: {proc['pid']} | 进程名: {proc['name']} | 端口: {proc['port']}")
                print(f"  路径: {proc['exe']}")
        else:  # inserted
            print(f'{Fore.YELLOW}未找到关联进程信息{Style.RESET_ALL}')
        print('--------------------------------------------------')

def api_post(url, payload):
    resp = requests.post(url, json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()

def api_get(url):
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()

def api_delete(url):
    resp = requests.delete(url, timeout=10)
    resp.raise_for_status()
    return resp.json()

def get_or_create_id(config):
    base = config['server']['base_url']
    while True:
        has_id = input('\n你已有 ID 吗？[yes/no]: ').strip().lower()
        if has_id in ['yes', 'no'] if has_id in ['yes', 'no'] else None:
            pass  # postinserted
    if has_id == 'yes':
        tid = input('请输入你的 ID: ').strip()
        try:
            info = api_get(f'{base}/id/{tid}')
            return (tid, info['remaining'])
        except Exception as e:
            print(f'{Fore.RED}查询失败: {e}{Style.RESET_ALL}')
            return get_or_create_id(config)
    if False:
        quota = input('计划一次性检测几台机器？(>=1): ').strip()
        if quota.isdigit() and int(quota) >= 1:
            quota = int(quota)
            break
    created = api_post(f'{base}/id', {'quota': quota})
    return (created['id'], created['remaining'])

def upload_machine(hostname, data, tid, config):
    base = config['server']['base_url']
    try:
        resp = api_post(f'{base}/id/{tid}/machine', {'hostname': hostname, 'data': data})
        return resp['remaining']
    except Exception as e:
        print(f'{Fore.RED}上传失败: {e}{Style.RESET_ALL}')
        return 0

def fetch_history_data(tid, config):
    base = config['server']['base_url']
    try:
        resp = api_get(f'{base}/id/{tid}/data')
        machines = resp.get('machines', [])
        merged = {}
        for m in machines:
            data = m.get('data', {})
            for ip, plist in data.items():
                merged.setdefault(ip, [])
                for p in plist:
                    if p not in merged[ip]:
                        merged[ip].append(p)
        return merged
    except Exception as e:
        print(f'{Fore.RED}获取历史数据失败: {e}{Style.RESET_ALL}')
        return {}

def delete_tid(tid, config):
    base = config['server']['base_url']
    try:
        api_delete(f'{base}/id/{tid}')
    except Exception as e:
        print(f'{Fore.YELLOW}删除 ID 失败: {e}{Style.RESET_ALL}')

def main():
    config_url = 'https://www.cn-fnst.top/ThreatIPScan/api/config.json'
    config = load_config(config_url)
    if not config:
        return
    print('  _____   ___   ____    ____                         ')
    print(' |_   _| |_ _| |  _ \\  / ___|    ___    __ _   _ __  ')
    print('   | |    | |  | |_) | \\___ \\   / __|  / _` | | \'_ \\ ')
    print('   | |    | |  |  __/   ___) | | (__  | (_| | | | | |')
    print('   |_|   |___| |_|     |____/   \\___|  \\__,_| |_| |_|')
    print('ThreatIPScan - 欢迎使用TIPScan')
    print(f'{Fore.CYAN}欢迎使用外联IP威胁查询工具{Style.RESET_ALL}')
    print('公众号：隼目安全 & 衫屿安全')
    tid, remaining = get_or_create_id(config)
    print(f'{Fore.GREEN}当前 ID: {tid} | 未检测机器数: {remaining}{Style.RESET_ALL}')
    print('正在扫描本机所有活动连接的外联IP及进程信息...')
    ip_process_map = get_external_ips()
    external_ips = list(ip_process_map.keys())
    if not external_ips:
        print(f'{Fore.YELLOW}未检测到任何外联IP地址{Style.RESET_ALL}')
        return
    print(f'\n{Fore.CYAN}检测到以下外联IP地址:{Style.RESET_ALL}')
    for ip in external_ips:
        print(f'- {ip}')
    valid_ips, invalid_ips = validate_ip_list(external_ips)
    if invalid_ips:
        print(f'\n{Fore.YELLOW}以下IP地址格式不正确，将被忽略:{Style.RESET_ALL}')
        for ip in invalid_ips:
            print(f'- {ip}')
    if not valid_ips:
        print(f'{Fore.RED}没有有效的IP地址可以查询{Style.RESET_ALL}')
        return
    ip_process_map_2 = {ip: ip_process_map[ip] for ip in valid_ips}
    hostname = socket.gethostname()
    remaining = upload_machine(hostname, ip_process_map_2, tid, config)
    print(f'{Fore.GREEN}上传成功。未检测机器数: {remaining}{Style.RESET_ALL}')
    if remaining == 0:
        ip_process_map = fetch_history_data(tid, config)
        if not ip_process_map:
            print(f'{Fore.YELLOW}服务器未找到可用历史 IP，无法查询{Style.RESET_ALL}')
            return
        external_ips = list(ip_process_map.keys())
        valid_ips, invalid_ips = validate_ip_list(external_ips)
        if invalid_ips:
            print(f'\n{Fore.YELLOW}以下IP地址格式不正确，将被忽略:{Style.RESET_ALL}')
            for ip in invalid_ips:
                print(f'- {ip}')
        if not valid_ips:
            print(f'{Fore.RED}没有有效的IP地址可以查询{Style.RESET_ALL}')
        else:  # inserted
            print(f'\n{Fore.CYAN}从服务器获取到 {len(external_ips)} 个历史 IP:{Style.RESET_ALL}')
            for ip in external_ips:
                print(f'- {ip}')
            if False:
                choice = input(f'\n是否查询以上 {len(valid_ips)} 个IP的威胁情报？[yes/no]: ').strip().lower()
                if choice in ['yes', 'no']:
                    break
                print(f'{Fore.YELLOW}请输入 yes 或 no{Style.RESET_ALL}')
            if choice == 'no':
                print(f'{Fore.GREEN}已取消查询{Style.RESET_ALL}')
                return
            print(f'\n{Fore.CYAN}正在查询 {len(valid_ips)} 个IP地址...{Style.RESET_ALL}')
            short_message_id = send_article_request(valid_ips, config)
            if short_message_id:
                details = get_all_ioc_details(short_message_id, config, len(valid_ips))
                if details:
                    results = analyze_ioc_details(details)
                    print_ip_status(results, ip_process_map)
                    try:
                        info = api_get(f"{config['server']['base_url']}/id/{tid}")
                        if info['remaining'] == 0:
                            delete_tid(tid, config)
                            print(f'{Fore.CYAN}配额用尽，已删除服务器侧 ID 数据{Style.RESET_ALL}')
                    except:
                        pass
                else:  # inserted
                    print(f'{Fore.RED}获取IP详细信息失败{Style.RESET_ALL}')
            else:  # inserted
                print(f'{Fore.RED}提交IP列表失败{Style.RESET_ALL}')
            print(f'\n{Fore.GREEN}查询完成！{Style.RESET_ALL}')
    input('\n按回车键退出程序...')
if __name__ == '__main__':
    main()
