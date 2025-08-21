import psutil
import socket
import requests
import json
import time
import hashlib
import os
import openpyxl
import webbrowser
from openpyxl.styles import Font, Alignment
from colorama import init, Fore, Style

# 初始化颜色库
init(autoreset=True)

# 当前版本号
CURRENT_VERSION = "1.5"

# 从远程地址加载配置
CONFIG_URL = "https://www.cn-fnst.top/ThreatIPScan/config.json"

class ThreatIntelligenceChecker:
    def __init__(self):
        self.load_config()
        
    def load_config(self):
        try:
            response = requests.get(CONFIG_URL, timeout=10)
            response.raise_for_status()
            config = response.json()
            
            # 检查版本更新
            latest_version = config.get("bb", CURRENT_VERSION)
            update_url = config.get("gxlj", "")
            
            if latest_version != CURRENT_VERSION:
                print(Fore.YELLOW + f"\n发现新版本 {latest_version} (当前版本: {CURRENT_VERSION})")
                choice = input("是否立即更新? (y/n): ").lower()
                if choice == 'y':
                    if update_url:
                        webbrowser.open(update_url)
                    exit(0)
                print()
            
            self.api_url = config["api_url"]
            self.headers_base = config.get("headers", {})
            self.auth_params = config.get("auth_params", {})
            
        except Exception as e:
            print(Fore.RED + f"❌ 无法加载远程配置文件，请检查网络连接或URL是否正确。错误信息：{e}")
            exit(1)

    def _generate_request_headers(self):
        ts = int(time.time())
        nonce = f"nonce_{ts}_{hashlib.md5(str(ts).encode()).hexdigest()[-8:]}"
        signature = f"signature_{hashlib.md5(nonce.encode()).hexdigest()[:32]}"
        return {
            **self.headers_base,
            "X-Cf-Ts": str(ts),
            "X-Cf-Nonce": nonce,
            "X-Cf-Signature": signature
        }

    def get_foreign_ips_with_process_info(self):
        connections = psutil.net_connections(kind='inet')
        local_ips = self.get_local_ips()
        foreign_ip_info = []

        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                if ':' not in remote_ip and remote_ip not in local_ips and not remote_ip.startswith('127.'):
                    try:
                        p = psutil.Process(conn.pid)
                        process_name = p.name()
                        process_path = p.exe()
                    except Exception:
                        process_name = "未知"
                        process_path = "未知"

                    foreign_ip_info.append({
                        "ip": remote_ip,
                        "pid": conn.pid,
                        "process_name": process_name,
                        "process_path": process_path
                    })
        return foreign_ip_info

    def get_local_ips(self):
        local_ips = set()
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    local_ips.add(addr.address)
        return local_ips

    def check_ip_reputation(self, ip):
        payload = {
            "object_key": ip,
            "common": self.auth_params
        }

        try:
            headers = self._generate_request_headers()
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=10
            )

            if response.status_code != 200:
                return None

            return response.json()
        except Exception as e:
            return None

    def display_result(self, ip, result):
        STATUS_MAP = {
            0: {"title": "未知信息", "color": Fore.MAGENTA},
            1: {"title": "未发现威胁", "color": Fore.CYAN},
            2: {"title": "已知安全", "color": Fore.GREEN},
            3: {"title": "已知威胁", "color": Fore.RED},
            4: {"title": "疑似威胁", "color": Fore.YELLOW},
            5: {"title": "未知信息", "color": Fore.MAGENTA},
            -1: {"title": "无效数据", "color": Fore.LIGHTBLACK_EX}
        }

        print(Fore.CYAN + "\n" + "=" * 60)
        print(Fore.YELLOW + f"威胁情报检测 - {ip}")
        print(Fore.CYAN + "=" * 60)

        if not result:
            print("❌ 检测失败：无返回数据")
            return

        result_status = result.get("result", {})
        if not isinstance(result_status, dict):
            print("❌ 检测失败：API响应格式错误")
            return

        if result_status.get("status") != 0:
            error_msg = result_status.get("msg", "未知错误")
            print(f"❌ API错误: {error_msg}")
            return

        data = result.get("data")
        if not data or not isinstance(data, dict):
            print("❌ 数据格式错误或为空")
            return

        reputation = data.get("reputation", {})
        try:
            category = int(reputation.get("category", -1))
        except (ValueError, TypeError):
            category = -1

        tags = reputation.get("tags", [])

        status_info = STATUS_MAP.get(category, STATUS_MAP[-1])
        color = status_info["color"]
        title = status_info["title"]

        print(f"{color}【{title}】{Style.RESET_ALL}")

        if tags:
            print("📌 威胁标签:")
            for tag in tags:
                print(f"- {tag.get('name', '未知')}")

    def run_local_detection(self):
        print(Fore.YELLOW + "\n正在扫描外联IP地址..." + Style.RESET_ALL)
        foreign_ip_info = self.get_foreign_ips_with_process_info()

        if not foreign_ip_info:
            print(Fore.GREEN + "✅ 未发现可疑外联连接")
            return

        print(Fore.CYAN + f"\n发现 {len(foreign_ip_info)} 个外联IP:")

        results = []
        for info in foreign_ip_info:
            print(f"IP: {info['ip']} | PID: {info['pid']} | 程序名: {info['process_name']}")
            print(f"程序路径: {info['process_path']}")
            print("-" * 60)

            result = self.check_ip_reputation(info['ip'])
            self.display_result(info['ip'], result)
            results.append({
                "ip": info['ip'],
                "pid": info['pid'],
                "process_name": info['process_name'],
                "process_path": info['process_path'],
                "result": result
            })

        export_choice = input(Fore.YELLOW + "\n是否将本机检测结果导出为 Excel 文件? (y/n): ").lower()
        if export_choice == 'y':
            self.export_to_excel(results, filename="local_results.xlsx")

    def run_batch_detection(self):
        file_path = "IP.txt"

        if not os.path.exists(file_path):
            with open(file_path, "w") as f:
                pass
            print(Fore.YELLOW + f"已创建文件 {file_path}，请在其中按行输入要检测的IP地址。")
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                ips = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(Fore.RED + f"读取文件失败: {e}")
            return

        ip_count = len(ips)
        if ip_count == 0:
            print(Fore.RED + "文件中没有有效的IP地址")
            return
        elif ip_count > 600:
            print(Fore.RED + f"文件中的IP地址数量 ({ip_count}) 超过了最大限制 (600)。")
            return

        print(Fore.CYAN + f"\n开始批量检测 {ip_count} 个IP..." + Style.RESET_ALL)
        results = []
        for ip in ips:
            print(f"\n检测 {ip}...")
            result = self.check_ip_reputation(ip)
            self.display_result(ip, result)
            results.append({"ip": ip, "result": result})

        export_choice = input(Fore.YELLOW + "\n是否将批量检测结果导出为 Excel 文件? (y/n): ").lower()
        if export_choice == 'y':
            self.export_to_excel(results, filename="batch_results.xlsx")

    def export_to_excel(self, results, filename="results.xlsx"):
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "检测结果"

        headers = ["IP地址", "状态", "威胁标签", "原始数据"]
        ws.append(headers)

        bold_font = Font(bold=True)
        for cell in ws["1"]:
            cell.font = bold_font
            cell.alignment = Alignment(horizontal="center")

        for item in results:
            ip = item["ip"]
            result = item.get("result", {})
            status = "未知"
            tags = ""

            if result and result.get("data"):
                rep = result["data"].get("reputation", {})
                category = int(rep.get("category", -1))
                tags_list = rep.get("tags", [])
                tags = ", ".join([t.get("name", "未知") for t in tags_list])

                status_map = {
                    0: "未知信息",
                    1: "未发现威胁",
                    2: "已知安全",
                    3: "已知威胁",
                    4: "疑似威胁",
                    5: "未知信息",
                    -1: "无效数据"
                }
                status = status_map.get(category, "未知")

            row = [
                ip,
                status,
                tags,
                json.dumps(result, ensure_ascii=False, indent=2)
            ]
            ws.append(row)

        for col in ws.columns:
            max_length = 0
            column = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = (max_length + 2)
            ws.column_dimensions[column].width = min(adjusted_width, 50)

        wb.save(filename)
        print(Fore.GREEN + f"\n✅ 结果已保存至 {filename}")

    def show_menu(self):
        while True:
            print('\n  _____   ___   ____    ____                         ')
            print(' |_   _| |_ _| |  _ \\  / ___|    ___    __ _   _ __  ')
            print('   | |    | |  | |_) | \\___ \\   / __|  / _` | | \'_ \\ ')
            print('   | |    | |  |  __/   ___) | | (__  | (_| | | | | |')
            print('   |_|   |___| |_|     |____/   \\___|  \\__,_| |_| |_|')
            print(f'ThreatIPScan - 欢迎使用TIPScan')
            print(f'{Fore.CYAN}欢迎使用外联IP威胁查询工具{Style.RESET_ALL}')
            print(f'当前版本: {CURRENT_VERSION}')
            print('公众号：隼目安全 & 衫屿安全\n')

            print("请选择操作模式：")
            print("1. 本机外联检测")
            print("2. 批量威胁情报检测")
            print("3. 退出")

            choice = input("\n请输入数字选择功能: ").strip()
            
            if choice == "1":
                self.run_local_detection()
            elif choice == "2":
                self.run_batch_detection()
            elif choice == "3":
                print(Fore.GREEN + "\n感谢使用，再见！")
                break
            else:
                print(Fore.RED + "\n输入无效，请重新输入。")


if __name__ == "__main__":
    try:
        import psutil
        import requests
        from colorama import Fore, Style
        import openpyxl
    except ImportError as e:
        print(Fore.RED + "需要安装依赖库:")
        print(Fore.WHITE + "pip install psutil requests colorama openpyxl")
        exit(1)

    checker = ThreatIntelligenceChecker()
    checker.show_menu()
