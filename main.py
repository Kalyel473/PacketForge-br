
import argparse
import base64
import re
import signal
import sys
import time
import os
from collections import Counter, defaultdict, deque
from datetime import datetime
from math import log2

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _Dummy:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Dummy()

try:
    from scapy.all import (
        sniff, wrpcap, rdpcap, get_if_list,
        IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
    )
except ImportError:
    print(f"{Fore.RED}[ERRO] O pacote 'scapy' não está instalado.")
    print(f"{Fore.YELLOW}Instale com: pip install scapy --break-system-packages")
    sys.exit(1)


BANNER = f"""{Fore.GREEN}
 ____           _        _   _____                    ____  ____
|  _ \\ __ _  ___| | _____| |_|  ___|__  _ __ __ _  ___ | __ )|  _ \\
| |_) / _` |/ __| |/ / _ \\ __| |_ / _ \\| '__/ _` |/ _ \\|  _ \\| |_) |
|  __/ (_| | (__|   <  __/ |_|  _| (_) | | | (_| |  __/| |_) |  _ <
|_|   \\__,_|\\___|_|\\_\\___|\\__|_|  \\___/|_|  \\__, |\\___||____/|_| \\_\\
                                            |___/
{Style.RESET_ALL}{Fore.CYAN}          Sniffer de pacotes estilo tcpdump - v2.0
          + Motor de Detecção de Ameaças (Blue Team)
          Cybersegurança na Prática | CyberGuard Academy{Style.RESET_ALL}
"""

DISCLAIMER = f"""{Fore.YELLOW}
[AVISO LEGAL] Uso permitido apenas em redes próprias ou com autorização
formal. Interceptação de comunicações sem consentimento pode violar a
Lei 12.737/2012 e a LGPD (Lei 13.709/2018). O uso indevido é de inteira
responsabilidade do usuário.{Style.RESET_ALL}
"""

PROTO_COLOR = {
    "TCP": Fore.GREEN,
    "UDP": Fore.YELLOW,
    "ICMP": Fore.MAGENTA,
    "ARP": Fore.CYAN,
    "DNS": Fore.BLUE,
    "IPv6": Fore.WHITE,
    "OUTRO": Fore.LIGHTBLACK_EX,
}

# Portas historicamente associadas a malware/backdoors/C2 (indicadores de comprometimento)
WATCHLIST_PORTS = {
    4444: "Meterpreter/Metasploit (payload padrão)",
    31337: "Back Orifice / porta 'elite' clássica de backdoor",
    1337: "Porta 'leet' comumente usada por malware/C2",
    6666: "Trojan genérico / IRC bot",
    6667: "IRC (canal comum de C2 histórico)",
    12345: "NetBus (backdoor clássico)",
    5555: "Android Debug Bridge exposto / backdoors",
    2323: "Telnet alternativo (alvo comum de botnets IoT, ex: Mirai)",
}

stats = Counter()
bytes_per_ip = Counter()
alert_counter = Counter()
start_time = None
captured_packets = []

# Estado do motor de detecção
port_scan_tracker = defaultdict(deque)   # src_ip -> deque[(timestamp, dst_port)]
arp_table = {}                            # ip -> mac já visto (para detectar spoofing)
ALERT_LOG_FILE = None
PORT_SCAN_WINDOW = 5
PORT_SCAN_THRESHOLD = 15


def calc_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * log2(c / length) for c in freq.values())


def alert(kind: str, message: str):
    ts = datetime.now().strftime("%H:%M:%S")
    alert_counter[kind] += 1
    print(f"{Fore.RED}{Style.BRIGHT}[ALERTA:{kind}] {ts} - {message}{Style.RESET_ALL}")
    if ALERT_LOG_FILE:
        try:
            with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] [{kind}] {message}\n")
        except OSError:
            pass


def detect_port_scan(pkt, threshold, window):
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    tcp = pkt[TCP]
    src = pkt[IP].src
    now = time.time()
    flags = str(tcp.flags)

    dq = port_scan_tracker[src]
    dq.append((now, tcp.dport))
    while dq and now - dq[0][0] > window:
        dq.popleft()
    unique_ports = {p for _, p in dq}
    if len(unique_ports) >= threshold:
        alert("PORT-SCAN", f"{src} tocou {len(unique_ports)} portas distintas em {window}s "
                            f"(possível varredura tipo Nmap)")
        dq.clear()

    if flags == "":
        alert("NULL-SCAN", f"{src} -> {pkt[IP].dst}:{tcp.dport} pacote TCP sem nenhuma flag (NULL scan)")
    elif flags == "F":
        alert("FIN-SCAN", f"{src} -> {pkt[IP].dst}:{tcp.dport} pacote TCP só com FIN (FIN scan)")
    elif set(flags) == {"F", "P", "U"}:
        alert("XMAS-SCAN", f"{src} -> {pkt[IP].dst}:{tcp.dport} pacote com FIN+PSH+URG (Xmas scan)")


def detect_arp_spoof(pkt):
    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    if arp.op == 2:  # is-at (resposta ARP)
        ip, mac = arp.psrc, arp.hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            alert("ARP-SPOOF", f"IP {ip} mudou de MAC {arp_table[ip]} para {mac} "
                                f"(possível ARP spoofing / ataque MITM)")
        arp_table[ip] = mac


def detect_plaintext_creds(pkt):
    if not (pkt.haslayer(Raw) and pkt.haslayer(IP)):
        return
    try:
        payload = bytes(pkt[Raw].load).decode(errors="ignore")
    except Exception:
        return
    src, dst = pkt[IP].src, pkt[IP].dst

    m = re.search(r"\b(USER|PASS)\s+(\S+)", payload, re.IGNORECASE)
    if m:
        alert("CREDENCIAL-TEXTO-CLARO",
              f"Comando FTP/Telnet '{m.group(1).upper()} {m.group(2)}' capturado de {src} -> {dst}")

    m2 = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", payload)
    if m2:
        try:
            decoded = base64.b64decode(m2.group(1) + "===").decode(errors="ignore")
            alert("HTTP-BASIC-AUTH", f"Credenciais HTTP Basic capturadas de {src} -> {dst}: {decoded}")
        except Exception:
            alert("HTTP-BASIC-AUTH", f"Header Authorization Basic detectado de {src} -> {dst}")

    if re.search(r"(password|senha|passwd|pwd)=", payload, re.IGNORECASE):
        alert("HTTP-LOGIN-FORM", f"Possível formulário de login em texto claro de {src} -> {dst}")


def detect_dns_exfil(pkt):
    if not (pkt.haslayer(DNS) and pkt.haslayer(IP)):
        return
    dns = pkt[DNS]
    if dns.qr == 0 and dns.qd:
        try:
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
        except Exception:
            return
        subdomain = qname.split(".")[0] if qname else ""
        entropy = calc_entropy(subdomain)
        if len(qname) > 50 or entropy > 3.5:
            alert("DNS-EXFIL?", f"Consulta DNS suspeita de {pkt[IP].src}: "
                                 f"'{qname[:60]}' (entropia={entropy:.2f}, tamanho={len(qname)})")


def check_watchlist_ports(pkt):
    if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
        return
    layer = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
    for port in (layer.sport, layer.dport):
        if port in WATCHLIST_PORTS:
            alert("PORTA-SUSPEITA", f"Tráfego na porta {port} ({WATCHLIST_PORTS[port]}) "
                                     f"entre {pkt[IP].src} e {pkt[IP].dst}")
            break


def run_detection_engine(pkt, threshold, window):
    detect_port_scan(pkt, threshold, window)
    detect_arp_spoof(pkt)
    detect_plaintext_creds(pkt)
    detect_dns_exfil(pkt)
    check_watchlist_ports(pkt)


def hexdump(data: bytes, length=16):
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {i:04x}   {hex_part:<{length*3}}  {ascii_part}")
    return "\n".join(lines)


def resolve_proto(pkt):
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    return "OUTRO"


def flags_to_str(tcp_layer):
    flag_map = {
        "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
        "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
    }
    return "".join(flag_map.get(c, c) for c in str(tcp_layer.flags))


def format_packet(pkt, index, no_resolve=True, show_hex=False):
    proto = resolve_proto(pkt)
    color = PROTO_COLOR.get(proto, Fore.WHITE)
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    src = dst = sport = dport = None
    extra = ""

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "quem-tem" if arp.op == 1 else "é-para"
        line = (f"{ts} {color}ARP{Style.RESET_ALL} {op} {arp.pdst} "
                f"informar {arp.psrc}")
    elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        src = ip_layer.src
        dst = ip_layer.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            flags = flags_to_str(tcp)
            extra = f"[{flags}] seq={tcp.seq} ack={tcp.ack} win={tcp.window}"
            if pkt.haslayer(Raw):
                extra += f" len={len(pkt[Raw].load)}"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            extra = f"len={udp.len}"
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                qr = "resposta" if dns.qr == 1 else "consulta"
                qname = dns.qd.qname.decode(errors="ignore") if dns.qd else "?"
                extra += f" DNS {qr}: {qname}"
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            extra = f"type={icmp.type} code={icmp.code}"

        port_str = f":{sport} > {dst}:{dport}" if sport else f" > {dst}"
        src_str = f"{src}" if sport else f"{src} > {dst}"
        line = f"{ts} {color}{proto}{Style.RESET_ALL} {src}{port_str if sport else ''} {extra}"
        if not sport:
            line = f"{ts} {color}{proto}{Style.RESET_ALL} {src} > {dst} {extra}"
    else:
        line = f"{ts} {color}{proto}{Style.RESET_ALL} {pkt.summary()}"

    out = f"{index:>5}  {line}"
    if show_hex and pkt.haslayer(Raw):
        out += "\n" + hexdump(bytes(pkt[Raw].load))
    return out


def make_callback(args, counter_ref):
    def callback(pkt):
        counter_ref[0] += 1
        proto = resolve_proto(pkt)
        stats[proto] += 1
        if pkt.haslayer(IP):
            bytes_per_ip[pkt[IP].src] += len(pkt)

        if args.detect:
            run_detection_engine(pkt, args.scan_threshold, args.scan_window)

        show = True
        if args.grep:
            payload = bytes(pkt[Raw].load).decode(errors="ignore") if pkt.haslayer(Raw) else ""
            show = args.grep.lower() in payload.lower()

        if show and not args.quiet:
            print(format_packet(pkt, counter_ref[0], show_hex=args.hexdump))

        if args.write:
            captured_packets.append(pkt)
        if args.count and counter_ref[0] >= args.count:
            raise KeyboardInterrupt
    return callback


def print_summary():
    global start_time
    elapsed = time.time() - start_time if start_time else 0
    total = sum(stats.values())
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN} RESUMO DA CAPTURA")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f" Pacotes capturados : {Fore.GREEN}{total}{Style.RESET_ALL}")
    print(f" Duração            : {elapsed:.2f}s")
    if elapsed > 0:
        print(f" Taxa média         : {total/elapsed:.2f} pacotes/s")
    print(f"\n Distribuição por protocolo:")
    for proto, count in stats.most_common():
        pct = (count / total * 100) if total else 0
        bar = "█" * int(pct / 4)
        color = PROTO_COLOR.get(proto, Fore.WHITE)
        print(f"   {color}{proto:<6}{Style.RESET_ALL} {count:>6}  {pct:5.1f}%  {bar}")

    if bytes_per_ip:
        print(f"\n Top 5 IPs por volume de tráfego:")
        for ip, total_bytes in bytes_per_ip.most_common(5):
            kb = total_bytes / 1024
            print(f"   {Fore.CYAN}{ip:<18}{Style.RESET_ALL} {kb:>8.1f} KB")

    if alert_counter:
        total_alerts = sum(alert_counter.values())
        print(f"\n{Fore.RED}{Style.BRIGHT} Alertas de segurança: {total_alerts}{Style.RESET_ALL}")
        for kind, count in alert_counter.most_common():
            print(f"   {Fore.RED}{kind:<22}{Style.RESET_ALL} {count}")
    print()


def list_interfaces():
    print(f"{Fore.CYAN}Interfaces de rede disponíveis:{Style.RESET_ALL}")
    for iface in get_if_list():
        print(f"  - {iface}")


def read_pcap_file(path, args):
    print(f"{Fore.CYAN}[*] Lendo arquivo pcap: {path}{Style.RESET_ALL}\n")
    packets = rdpcap(path)
    counter_ref = [0]
    for pkt in packets:
        counter_ref[0] += 1
        proto = resolve_proto(pkt)
        stats[proto] += 1
        if pkt.haslayer(IP):
            bytes_per_ip[pkt[IP].src] += len(pkt)

        if args.detect:
            run_detection_engine(pkt, args.scan_threshold, args.scan_window)

        show = True
        if args.grep:
            payload = bytes(pkt[Raw].load).decode(errors="ignore") if pkt.haslayer(Raw) else ""
            show = args.grep.lower() in payload.lower()

        if show and not args.quiet:
            print(format_packet(pkt, counter_ref[0], show_hex=args.hexdump))

        if args.count and counter_ref[0] >= args.count:
            break
    global start_time
    start_time = time.time() - 0.001
    print_summary()


def main():
    parser = argparse.ArgumentParser(
        prog="packetforge_br.py",
        description="PacketForge BR - Sniffer de pacotes estilo tcpdump em Python",
        epilog="Exemplo: sudo python3 packetforge_br.py -i eth0 -f 'tcp port 80' -c 50 -X"
    )
    parser.add_argument("-i", "--interface", help="Interface de rede (ex: eth0, wlan0)")
    parser.add_argument("-f", "--filter", default="", help="Filtro BPF (ex: 'tcp port 443', 'udp', 'icmp')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Número de pacotes a capturar (0 = infinito)")
    parser.add_argument("-X", "--hexdump", action="store_true", help="Exibir payload em hexdump + ASCII")
    parser.add_argument("-w", "--write", metavar="ARQUIVO.pcap", help="Salvar pacotes capturados em arquivo .pcap")
    parser.add_argument("-r", "--read", metavar="ARQUIVO.pcap", help="Ler e analisar pacotes de um arquivo .pcap")
    parser.add_argument("-D", "--list-interfaces", action="store_true", help="Listar interfaces disponíveis e sair")
    parser.add_argument("--no-banner", action="store_true", help="Não exibir banner inicial")
    parser.add_argument("--detect", action="store_true",
                         help="Ativar motor de detecção de ameaças (port scan, ARP spoofing, "
                              "credenciais em texto claro, DNS exfiltration, portas suspeitas/IOC)")
    parser.add_argument("--alert-log", metavar="ARQUIVO.log",
                         help="Salvar alertas de segurança em arquivo de log (usar com --detect)")
    parser.add_argument("-q", "--quiet", action="store_true",
                         help="Modo silencioso: não exibe cada pacote, só alertas e o resumo final")
    parser.add_argument("-g", "--grep", metavar="TEXTO",
                         help="Exibir apenas pacotes cujo payload contenha o texto informado")
    parser.add_argument("--scan-threshold", type=int, default=15,
                         help="Nº de portas distintas para acusar port scan (padrão: 15)")
    parser.add_argument("--scan-window", type=int, default=5,
                         help="Janela de tempo em segundos para detecção de port scan (padrão: 5)")

    args = parser.parse_args()

    global ALERT_LOG_FILE
    ALERT_LOG_FILE = args.alert_log

    if not args.no_banner:
        print(BANNER)
        print(DISCLAIMER)
        if args.detect:
            print(f"{Fore.GREEN}[+] Motor de detecção de ameaças: ATIVADO "
                  f"(port scan, ARP spoof, credenciais em texto claro, DNS exfil, portas IOC){Style.RESET_ALL}")
            if args.alert_log:
                print(f"{Fore.GREEN}[+] Alertas serão salvos em: {args.alert_log}{Style.RESET_ALL}")

    if args.list_interfaces:
        list_interfaces()
        return

    if args.read:
        read_pcap_file(args.read, args)
        return

    if os.geteuid() != 0:
        print(f"{Fore.RED}[ERRO] Este script precisa ser executado como root/sudo "
              f"para capturar pacotes em modo raw.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Exemplo: sudo python3 packetforge_br.py -i eth0{Style.RESET_ALL}")
        sys.exit(1)

    global start_time
    start_time = time.time()
    counter_ref = [0]

    iface_msg = args.interface if args.interface else "todas as interfaces"
    filtro_msg = args.filter if args.filter else "nenhum (captura tudo)"
    print(f"{Fore.CYAN}[*] Escutando em: {iface_msg}")
    print(f"[*] Filtro BPF  : {filtro_msg}")
    print(f"[*] Pressione Ctrl+C para parar a captura{Style.RESET_ALL}\n")

    def handle_sigint(sig, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        sniff(
            iface=args.interface if args.interface else None,
            filter=args.filter if args.filter else None,
            prn=make_callback(args, counter_ref),
            store=False,
            count=args.count if args.count else 0,
        )
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"{Fore.RED}[ERRO] Falha ao abrir interface: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Use -D para listar interfaces disponíveis.{Style.RESET_ALL}")
        sys.exit(1)
    finally:
        print_summary()
        if args.write and captured_packets:
            wrpcap(args.write, captured_packets)
            print(f"{Fore.GREEN}[+] {len(captured_packets)} pacotes salvos em: {args.write}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()