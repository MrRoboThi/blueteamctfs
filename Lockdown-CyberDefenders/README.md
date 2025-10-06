# Análise Forense e Resposta a Incidentes: Estudo de Caso "Lockdown" (CyberDefenders)

# Autor: Thiago Azevedo dos Santos Pereira
# Data da Análise: 05 de Outubro de 2025
Link do Desafio: [[Lockdown - CyberDefenders](https://cyberdefenders.org/blueteam-labs/lockdown)
](https://cyberdefenders.org/blueteam-ctf-challenges/lockdown/)
---

# 1. Sumário Executivo

Este relatório detalha a análise forense de um incidente de segurança no desafio "Lockdown". A investigação revelou um comprometimento de um servidor web IIS, iniciado por uma enumeração de serviços de rede, seguida pela entrega de um payload malicioso (AgentTesla) via SMB. O atacante estabeleceu persistência e comando e controle através de um **reverse shell**, que é caracterizado pela conexão feita da máquina-alvo para a máquina do atacante. A análise combinou evidências de rede (.pcap), memória (.mem) e do executável malicioso para reconstruir a cadeia de ataque completa.

---

# 2. Cadeia de Custódia e Evidências

As seguintes evidências foram analisadas:


| capture.pcapng | Captura de Pacotes de Rede 
| memdump.mem | Dump de Memória RAM 
| updatenow.exe | Artefato Malicioso 

---

# 3. Ferramentas Utilizadas
* **Análise de Rede:** Wireshark
* **Análise de Malware Estática:** VirusTotal
* **Análise de Memória:** Volatility 3 Framework
* **Reconhecimento de técnicas usada:** Mitre Att&ck

---

# 4. Análise Cronológica (Cadeia do Ataque)

A investigação revelou a seguinte sequência de ações do atacante:

1.  Reconhecimento: O atacante realizou uma varredura de serviços na rede do alvo.
2.  Entrega do Payload: Utilizando o protocolo SMB2, o atacante escreveu um arquivo` no compartilhamento de rede afetado.
3.  Execução e Comando & Controle (C2): O malware foi executado no servidor IIS. A análise de memória confirmou que havia um processo na máquina que estabeleceu um reverse shell (conexão TCP de longa duração) para o IP do atacante.

---

# 5. Análise Detalhada dos Artefatos

# 5.1. Análise de Rede (PCAP)
  
  # Filtro usado para isolar o tráfego de reconhecimento inicial
  http.request.method==GET 

  Com esse comando eu pude analisar as requisições GET enviadas para o IP do servidor e pude identificar o IP malicioso.
    
  # Filtro usado para encontrar a escrita do arquivo de malware
  smb2.tree
  
  A partir desse comando, um dos pacotes mostra a requisição de escrita (Write Request) com o nome e o tamanho do arquivo malicioso.
  
  # Filtro usado para isolar a comunicação C2
  ip.src==10.0.2.15 && ip.dst==10.0.2.4 && tcp
  
  A análise desta conversa TCP revelou uma conexão persistente, característica de um shell interativo. Com esse comando fui capaz de compreender a porta utilizada para a escuta do atacante a partir do shell reverso.

# 5.2. Análise de Malware (Estática)
O arquivo updatenow.exe foi enviado ao VirusTotal, com os seguintes resultados:
Família do Malware: Identificado como AgentTesla
Técnica de Anti-Forense: Detectado o uso do empacotador UPX.
Indicador de Comprometimento (IoC): O malware se comunica com o host de C2 cp8nl.hyperhost.ua

# 5.3. Análise de Memória (Volatility 3)

  # Comando usado para encontrar a kernel base
  python3 vol.py -f memdump.mem windows.info

  # Comando para encontrar o local do malware
  python3 vol.py -f memdump.mem windows.cmdline

  Esse comando permitiu que eu analisasse os processos e seus caminhos, revelando como o malware foi executado.

  # Comando para listar os processos ativos
  python3 vol.py -f memdump.mem windows.pslist
 
  Com esse comando foi possível encontrar o processo do sistema que está comprometido e seu PID.
  # Comando de confirmação da Conexão de Rede:
  python3 vol.py -f Lockdown-memory.vmem windows.netscan

  Com esse comando foi possível confirmar que o processo encontrado realmente conversava com o IP atacante. 
---

# 6. Mapeamento MITRE ATT&CK®

# Táticas: Discovery, Persistence, Execution, Defense Evasion, Command and control
# Técnicas: Network Service Discovery, Boot or logon Autostart Execution, Command and scripting interpreter, Obfuscated Files or Information, Remote Access Tools
---

# 7. Conclusão e Recomendações

  # Conclusão
  O servidor foi comprometido por um ator malicioso externo. O invasor executou uma fase de reconhecimento para identificar serviços abertos, explorando com sucesso o protocolo SMB para transferir uma ferramenta maliciosa a partir da conexão bem sucedida. O malware, identificado como um trojan da família AgentTesla, estabeleceu um canal de Comando e Controle (C2) através de um reverse shell quando foi executado, concedendo ao atacante acesso interativo ao sistema comprometido. A utilização de técnicas de ofuscação como o upx evidencia a intenção do atacante em evadir as defesas de segurança.

  # Recomendações
  1. Isolar o host comprometido para impedir táticas de movimento lateral.
  2. Bloquear no firewall todas as conexões vindas do IP malicioso e do domínio de controle e comando identificado.
  3. Remover o arquivo malicioso
  4. Fazer uma varredura completa no sistema em busca de mecanismos de persistência que possam ter sido criados pelo malware
  5. Revisar a configuração do serviço SMB, seguindo o princípio do menor privilégio.
  6. Fazer o reset de todas as credenciais
  7. Restaurar um backup limpo de uma data anterior ao comprometimento do host.
  8. Implementar um monitoramento para o servidor após a recuperação.
---
