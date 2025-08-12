# edr2nessus

Ferramenta para consolidar inventário de ativos Windows a partir de exports do **SentinelOne** e **CrowdStrike Falcon** e cruzar com um "database" de vulnerabilidades do **Nessus** (criado a partir de outro script personalizado) , gerando uma visão clara de cobertura de varreduras autenticadas.

## Funcionalidades

- Importa inventários de ativos do **SentinelOne** e **CrowdStrike Falcon** (CSV exportados dos consoles).
- Importa "database" do **Nessus**:
  - CSV gerado pelo script `nessus_to_csv.py`, ou
  - CSV/planilha já consolidada (host-level) com colunas `Hostname` e `Credentialed Scan`.
- Considera **apenas ativos Windows**.
- Match de hosts por **hostname normalizado** (remove domínio e `$`) ↔ `netbios_name` do Nessus.
- Marca cobertura de scan (`Nessus=true`) **apenas** quando houver varredura autenticada (`Credentialed_Scan=true`).
- Normaliza:
  - Datas `Last Seen` para **`dd/MM/yyyy`**.
  - Sistemas operacionais para formato padronizado (`Microsoft Windows X` ou `Microsoft Windows Server YYYY [R2]`).
- Saída em **Excel** com múltiplas abas:
  - `Inventario - Workstation`
  - `Inventario - Servers`
  - `SentinelOne` (limpo)
  - `FalconCS` (limpo)
  - `Nessus` (host-level)

## Estrutura do Projeto

```
.
├── edr_nessus_inventory.py      # Script principal
├── README.md
└── requirements.txt              # Dependências Python
```

## Instalação

Clone o repositório e instale as dependências:

```bash
git clone https://github.com/0xdryleaf/edr2nessus.git
cd edr2nessus
pip install -r requirements.txt
```

**requirements.txt** sugerido:
```
pandas
numpy
xlsxwriter
```

## Uso

### Sintaxe
```bash
python edr2nessus.py -s sentinelone.csv -c crowdstrike.csv -n nessus.csv -o output_file.xlsx
```

### Parâmetros
| Parâmetro               | Alias   | Descrição |
|-------------------------|---------|-----------|
| `--sentinel`            | `-s`  | CSV export do SentinelOne |
| `--crowdstrike`         | `-c`  | CSV export do CrowdStrike Falcon |
| `--nessus`              | `-n`  | CSV do Nessus (database ou host-level) |
| `--output`              | `-o`  | Nome do arquivo de saída Excel |
| `--man`                 | `-h`  | Exibe manual detalhado |


## Saída

Arquivo Excel com as abas:
- **Inventario - Workstation**: apenas workstations.
- **Inventario - Servers**: apenas servidores.
- **SentinelOne**: inventário bruto do S1 filtrado para Windows.
- **FalconCS**: inventário bruto do CS filtrado para Windows.
- **Nessus**: inventário host-level com status de scan autenticado.


## Licença
Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.
