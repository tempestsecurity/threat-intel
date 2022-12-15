# Nova campanha do Chaes usa o Windows Management Instrumentation Command-Line Utility

#### _Threat Intelligence Team_

Esse arquivo contempla os IoCs, as oportunidades de detecção e as técnicas do Mitre ATT&CK identificadas na recente campanha do Chaes. Detalhes sobre o malware foram enviados numa análise completa aos clientes do serviço Threat Intelligence.

## IOCs
- [Chaes.csv](https://github.com/tempestsecurity/threat-intel/blob/master/iocs/Nova_campanha_do_Chaes_usa_o_Windows_Management_Instrumentation_Command-Line_Utility.csv) - Chaes malware Indicator of Compromise (IOC)

## Oportunidades de detecção

#### 1

| Requisito de coleta | Windows Event Log|
| ------ | ------ |
| Data Source | [DS0017](https://attack.mitre.org/datasources/DS0017)|
| Oportunidade | O python.exe é renomeado para um nome aleatório e é executado a partir do path "..\AppData\Roaming\"|
| Comportamento | Exemplo "C:\Users\<USER>\AppData\Roaming\Bdijgozdugtk\Jwmxmrdbfe\Jwmxmrdbfe\Jwmxmrdbfe.exe qsoten Jwmxmrdbfe.json QzpcUHJvZ3JhbSBGaWxlc1xHb29nbGVcQ2hyb21lXEFwcGxpY2F0aW9uXGNocm9tZS5leGU="|
| Lógica de detecção | parent_original_name == python.exe AND file_path_contains == '\AppData\Roaming\'  |

#### 2

| Requisito de coleta | Windows Event Log|
| ------ | ------ |
| Data Source | [DS0017](https://attack.mitre.org/datasources/DS0017)|
| Oportunidade | O pythonw.exe é renomeado para um nome aleatório e é executado a partir do path "..\AppData\Roaming\"|
| Comportamento | Exemplo "C:\Users\<USER>\AppData\Roaming\Bdijgozdugtk\Jwmxmrdbfe\Jwmxmrdbfe\Jwmxmrdbfe.exe qsoten Jwmxmrdbfe.json QzpcUHJvZ3JhbSBGaWxlc1xHb29nbGVcQ2hyb21lXEFwcGxpY2F0aW9uXGNocm9tZS5leGU="|
| Lógica de detecção | parent_original_name == pythonw.exe AND file_path_contains == '\AppData\Roaming\'  |

#### 3

| Requisito de coleta | Windows Event Log |
| ------ | ------ |
| Data Source | [DS0017](https://attack.mitre.org/datasources/DS0017) |
| Oportunidade | O node.exe é renomeado para um nome aleatório e é executado a partir do path "..\AppData\Roaming\" |
| Comportamento | O NodeJS é executado e os scripts são escritos diretamente na linha de comando, portanto, não existem logs demonstrando as execuções dos scripts. |
| Lógica de detecção | parent_original_name == node.exe AND file_path_contains == '\AppData\Roaming\' |

#### 4

| Requisito de coleta | Windows Event Log |
| ------ | ------ |
| Data Source | [DS0017](https://attack.mitre.org/datasources/DS0017) |
| Oportunidade | Em um dos estágios da ameaça, um script Python é coleta diversas informações do computador da vítima usando do binário wmic.exe, executado por meio do cmd.exe |
| Comportamento | Exemplo da coleta de dados efetuada por uma das fases do malware, "cmd.exe /c "wmic process get Caption,Commandline,Processid,ParentProcessId /format:list" "  |
| Lógica de detecção | parent_image == cmd.exe AND image == wmic.exe AND ( command_line_contains == csproduct get uuid OR command_line_contains == process get Caption,Commandline,Processid,ParentProcessId /format:list OR command_line_contains == bios get /format:list OR command_line_contains == LOGICALDISK GET Caption,DeviceID,Description,FileSystem,FreeSpace,Name,ProviderName,Size,VolumeName,VolumeSerialNumber /format:list OR command_line_contains == ComputerSystem get TotalPhysicalMemory /format:list OR command_line_contains == cpu get name, numberofcores /format:list OR command_line_contains ==volume where (DriveLetter LIKE "%s%%") get Capacity,SerialNumber,FreeSpace /format:list OR command_line_contains ==PROCESS WHERE \"name like \"% {processName} %\" AND NOT CommandLine LIKE \'%{}type%\' AND NOT CommandLine LIKE \'%{-}-user-data-dir%\'\" CALL TERMINATE) |

#### 5

| Requisito de coleta | Windows Event Log |
| ------ | ------ |
| Data Source | [DS0017](https://attack.mitre.org/datasources/DS0017) |
| Oportunidade | O cmd.exe é utilizado para instalar diversos módulos do NodeJS que são necessários para que uma das fases do malware seja iniciada.  |
| Comportamento | Exemplo do comando utilizado para instalar os módulos do NodeJS, "cmd.exe /c Nshxkccoawhn\npm.cmd install ws puppeteer-core puppeteer-extra puppeteer-extra-plugin-stealth axios"  |
| Lógica de detecção | parent_image == cmd.exe AND command_line_contains == puppeteer AND ws AND axios|