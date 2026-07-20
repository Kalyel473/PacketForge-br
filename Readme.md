# PacketForge BR 🐍📡

Sniffer e analisador de pacotes de rede em Python, com CLI inspirada no **tcpdump**  agora com **motor de detecção de ameaças (modo Blue Team)**  

## O que ele faz

### Sniffer (estilo tcpdump)
- Captura pacotes em tempo real (TCP, UDP, ICMP, ARP, DNS) usando filtros BPF, igual ao tcpdump
- Saída colorida no terminal, com cores diferentes por protocolo
- Modo hexdump (`-X`) para ver o payload em hex + ASCII
- Salva a captura em `.pcap` (`-w`) para abrir depois no Wireshark
- Lê e analisa arquivos `.pcap` já existentes (`-r`)
- Filtro de conteúdo estilo grep (`-g`) — mostra só pacotes cujo payload contém o texto buscado
- Lista as interfaces de rede disponíveis (`-D`)
- Resumo estatístico ao final: distribuição por protocolo e **top 5 IPs por volume de tráfego**

### 🛡️ Motor de detecção de ameaças (`--detect`)
- **Port scan** — detecta um IP tocando muitas portas distintas em pouco tempo (varredura tipo Nmap)
- **NULL / FIN / Xmas scan** — identifica os scans furtivos clássicos pelas combinações de flags TCP
- **ARP Spoofing** — alerta quando o mesmo IP passa a responder com um MAC diferente (indício de ataque MITM)
- **Credenciais em texto claro** — captura comandos FTP/Telnet (`USER`/`PASS`), headers `Authorization: Basic` (decodifica o Base64) e formulários HTTP de login sem criptografia
- **Possível exfiltração via DNS** — heurística por entropia e tamanho do subdomínio consultado
- **Portas suspeitas / IOC** — alerta sobre tráfego em portas historicamente associadas a backdoors e C2 (4444, 31337, 1337, 6667, 12345, etc.)
- Log de alertas em arquivo (`--alert-log`) e modo silencioso (`-q`) que mostra só os alertas + resumo

## Requisitos

```bash
pip install scapy colorama --break-system-packages
```

Python 3.9+. Testado em Linux (recomendado). Requer privilégios de root para capturar pacotes ao vivo (raw sockets) — igual ao tcpdump.

## Uso básico

```bash
# Listar interfaces disponíveis
python3 packetforge_br.py -D

# Capturar tudo na interface eth0
sudo python3 packetforge_br.py -i eth0

# Capturar só tráfego HTTP, limitado a 50 pacotes
sudo python3 packetforge_br.py -i eth0 -f "tcp port 80" -c 50

# Capturar com hexdump do payload
sudo python3 packetforge_br.py -i eth0 -X

# Capturar e salvar em pcap para abrir no Wireshark depois
sudo python3 packetforge_br.py -i eth0 -w captura.pcap

# Analisar um pcap já existente (não precisa de root)
python3 packetforge_br.py -r captura.pcap
```

## Uso do modo detecção (Blue Team)

```bash
# Ativar detecção de ameaças ao vivo, com log de alertas e modo silencioso
sudo python3 packetforge_br.py -i eth0 --detect -q --alert-log alertas.log

# Analisar um pcap em busca de ataques (ex: capturado no Wireshark)
python3 packetforge_br.py -r captura.pcap --detect

# Ajustar sensibilidade do detector de port scan
sudo python3 packetforge_br.py -i eth0 --detect --scan-threshold 10 --scan-window 3

# Buscar uma palavra específica no payload (ex: procurar "senha" em texto claro)
sudo python3 packetforge_br.py -i eth0 --detect -g "senha"
```

## Opções (estilo tcpdump)

| Flag | Descrição |
|------|-----------|
| `-i` | Interface de rede (eth0, wlan0, etc.) |
| `-f` | Filtro BPF (`"tcp port 443"`, `"udp"`, `"icmp"`, `"host 8.8.8.8"`...) |
| `-c` | Número de pacotes a capturar (0 = infinito, Ctrl+C para parar) |
| `-X` | Exibe hexdump + ASCII do payload |
| `-w` | Salva os pacotes capturados em arquivo `.pcap` |
| `-r` | Lê e analisa um arquivo `.pcap` existente |
| `-D` | Lista as interfaces de rede disponíveis |
| `-g` | Mostra só pacotes cujo payload contém o texto buscado |
| `-q` | Modo silencioso: só mostra alertas e o resumo final |
| `--detect` | Ativa o motor de detecção de ameaças |
| `--alert-log` | Salva os alertas em um arquivo de log |
| `--scan-threshold` | Nº de portas distintas para acusar port scan (padrão: 15) |
| `--scan-window` | Janela de tempo (segundos) para detecção de port scan (padrão: 5) |

## ⚠️ Aviso legal

Este software captura tráfego de rede em tempo real. Use **somente** em:
- Redes e dispositivos de sua propriedade
- Laboratórios controlados (VMs isoladas, Metasploitable, etc.)
- Redes com autorização formal e explícita do responsável

A interceptação de comunicações sem autorização pode configurar crime previsto na **Lei nº 12.737/2012** (Lei Carolina Dieckmann) e violar a **LGPD** (Lei nº 13.709/2018). O uso indevido desta ferramenta é de responsabilidade exclusiva de quem a utiliza.

