# SQLI RASP EXPERIMENT

Repositório de experimento reprodutível para avaliação de comportamento de detecção/bloqueio de SQL Injection no WebGoat com OWASP ZAP, variando exclusivamente o estado do OpenRASP:

- `RASP-ON`
- `RASP-OFF`

O desenho experimental mantém fixa a infraestrutura de rede (Gateway + Sidecars) e varia apenas o estado do RASP.

## 1. Objetivo Científico

Medir diferenças de comportamento de segurança e observabilidade entre `RASP-ON` e `RASP-OFF` em uma topologia Kubernetes constante, usando:

- seed de tráfego autenticado
- varredura OWASP ZAP (spider + active scan)
- classificação por requisição (`waf`, `rasp`, `none`) no pipeline

## 2. Escopo e Variáveis

Variável independente:

- Estado do RASP (`on/off`) via `JAVA_TOOL_OPTIONS` no deployment `webgoat`

Variáveis controladas:

- Gateway sempre presente (`api-gateway`)
- Sidecar sempre presente (`webgoat`)
- Engine ModSecurity desativada (`MODSEC_RULE_ENGINE=Off`) em ambos os cenários
- Namespace, serviços, imagens e roteamento idênticos entre os cenários

## 3. Estrutura do Repositório

- `k8s/base/`: manifests base da topologia
- `k8s/profiles/rasp-on/`: overlay para cenário `RASP-ON`
- `k8s/profiles/rasp-off/`: overlay para cenário `RASP-OFF`
- `scripts/rasp_toggle_experiment_zap.py`: execução e consolidação de resultados
- `scripts/rasp_toggle_experiment_zap_lib.py`: biblioteca operacional (deploy/proxy/ZAP)
- `results/`: artefatos gerados por execução
- `Makefile`: atalhos de build/deploy/run

## 4. Arquitetura do Experimento

A arquitetura foi construída para isolar o efeito do RASP no comportamento da aplicação. A topologia Kubernetes permanece idêntica nos dois cenários; apenas a inicialização do OpenRASP dentro do WebGoat é modificada.

Componentes principais:

- `OWASP ZAP`: executa o seed autenticado, spider e active scan.
- `kubectl port-forward`: expõe o `Service` do gateway localmente na porta `18080`.
- `api-gateway`: ponto único de entrada HTTP da aplicação.
- `webgoat-sidecar`: proxy NGINX local ao pod do WebGoat.
- `webgoat`: aplicação vulnerável instrumentada com OpenRASP quando o perfil `rasp-on` está ativo.

Fluxo lógico:

```text
OWASP ZAP
  -> localhost:18080
  -> kubectl port-forward
  -> svc/api-gateway:8080
  -> pod/api-gateway
  -> svc/webgoat:8081
  -> pod/webgoat:webgoat-sidecar:8081
  -> pod/webgoat:webgoat:8080
  -> OpenRASP (quando ativo)
  -> WebGoat
```

O gateway permanece ativo nos dois cenários, mas a engine ModSecurity fica desligada por configuração (`MODSEC_RULE_ENGINE=Off`). Assim, bloqueios classificados como `rasp` decorrem do OpenRASP, enquanto bloqueios classificados como `waf` indicariam comportamento inesperado para esta configuração.

## 5. Trace da Requisição

O runner configura o OWASP ZAP como proxy HTTP da sessão de teste. Por isso, cada requisição emitida durante o seed, spider e active scan passa pelo ZAP antes de alcançar o gateway Kubernetes.

Para a rota vulnerável do WebGoat, o caminho observado é:

```text
ZAP -> Gateway -> Service webgoat -> Sidecar NGINX -> WebGoat JVM -> OpenRASP hook -> controlador WebGoat
```

No perfil `rasp-on`, a JVM do WebGoat é iniciada com `JAVA_TOOL_OPTIONS` apontando para o agente OpenRASP. O RASP instrumenta a execução da aplicação e pode detectar SQL Injection durante o processamento interno da requisição, não apenas pela inspeção externa do payload HTTP. Quando há evidência de atuação do RASP, o runner registra sinais como header `X-Protected-By: OpenRASP`, redirects de bloqueio ou outros indícios classificados como `layer=rasp`.

No perfil `rasp-off`, `JAVA_TOOL_OPTIONS` é esvaziado. A requisição percorre a mesma topologia, mas chega ao WebGoat sem instrumentação RASP. Nesse caso, a classificação esperada para payloads SQLi não bloqueados é `layer=none`.

O arquivo `results/zap-<ts>.requests.csv` contém a classificação por mensagem observada pelo ZAP. As colunas mais úteis para auditar o trace são:

- `profile`: cenário executado (`rasp-on` ou `rasp-off`)
- `phase`: origem da mensagem (`seed` ou `scan`)
- `method`, `url`, `status_code`: metadados HTTP
- `is_sqli_like`, `sqli_marker`: identificação heurística de payload SQLi
- `sqli_pattern_type`: categoria do padrão identificado (`boolean_based`, `time_based`, `union_based`, `metadata_probe`, etc.)
- `sqli_score`: score heurístico de 0 a 4, onde valores maiores indicam padrão SQLi mais forte
- `sqli_evidence`: evidência estruturada usada para classificar a requisição
- `layer`: camada que bloqueou ou classificou a resposta (`rasp`, `waf`, `none`)
- `evidence`: evidência usada para a classificação
- `request_params`, `response_excerpt`: recortes para inspeção manual

## 6. Payloads de SQL Injection

O experimento usa duas fontes de payloads SQLi, com propósitos diferentes.

A primeira fonte é um probe estático e controlado definido no próprio runner. Antes do spider e do active scan, o script autentica no WebGoat e envia uma requisição benigna e uma requisição SQLi para a rota `POST /webgoat/WebGoat/SqlInjection/attack8`.

Payload benigno:

```text
name=Smith
auth_tan=3SL99A
```

Payload SQLi controlado:

```text
name=Smith' OR '1'='1' --
auth_tan=x
```

Esse probe é customizado no experimento para gerar uma medição comparável entre `rasp-on` e `rasp-off`. Ele alimenta as métricas diretas `safe_status`, `sqli_status`, `safe_time_s`, `sqli_time_s` e `detector`.

A segunda fonte vem do próprio OWASP ZAP. Após o seed autenticado, o runner chama a API do ZAP para executar:

```text
spider -> active scan
```

Durante o active scan, os payloads SQLi são gerados pelos scanners internos do ZAP, não pelo script do experimento. Esses payloads variam conforme as regras e plugins disponíveis na imagem `ghcr.io/zaproxy/zaproxy:stable`, o estado da sessão autenticada, os parâmetros descobertos pelo spider e a superfície alcançável da aplicação.

O array `SQLI_MARKERS` e os padrões em `SQLI_PATTERNS` no script não são listas de payloads usados para atacar a aplicação. Eles são heurísticas de pós-processamento: o runner consulta as mensagens registradas pelo ZAP e procura padrões comuns de SQLi em URL, query string e corpo da requisição. Quando encontra um padrão, marca a linha em `requests.csv` como `is_sqli_like=1`, registra o padrão em `sqli_marker`, classifica a família em `sqli_pattern_type` e atribui um `sqli_score`.

Resumo operacional:

- Payload estático do experimento: usado no probe controlado antes do scan.
- Payloads do ZAP: usados durante o active scan e controlados pelos scanners internos do ZAP.
- `SQLI_MARKERS`: usado apenas para classificar mensagens observadas no tráfego, não para gerar requisições.

## 7. Foco SQLi e Probes

No experimento, uma probe é uma requisição controlada enviada pelo script antes do active scan do ZAP. Ela passa pelo proxy do ZAP e serve para:

- registrar no histórico do ZAP o endpoint exato, método HTTP, parâmetros e sessão
- medir uma resposta benigna e uma resposta maliciosa de forma comparável
- ajudar o active scan a ter contexto real do endpoint

O foco padrão é a rota:

```text
POST /webgoat/WebGoat/SqlInjection/attack8
```

Esse endpoint é usado como baseline porque testa confidencialidade com campos simples (`name`, `auth_tan`), monta SQL dinamicamente e não depende de alterações destrutivas no banco.

Probe benigna:

```text
name=Smith
auth_tan=3SL99A
```

Probe SQLi:

```text
name=Smith' OR '1'='1' --
auth_tan=x
```

### 7.1 Endpoints adicionais relevantes

O WebGoat também possui endpoints SQLi úteis para cenários separados:

```text
POST /webgoat/WebGoat/SqlInjection/attack9
POST /webgoat/WebGoat/SqlInjection/attack10
```

O `/attack9` testa integridade. Ele usa os mesmos parâmetros do `/attack8`, mas aceita stacked queries que podem alterar dados, como salário de funcionário.

Exemplo de probe benigna:

```text
name=Smith
auth_tan=3SL99A
```

Exemplo de payload de integridade:

```text
name=Smith
auth_tan=3SL99A'; UPDATE employees SET salary = '300000' WHERE last_name = 'Smith
```

O `/attack10` testa disponibilidade. Ele recebe `action_string` e consulta a tabela `access_log`. Um payload destrutivo pode remover essa tabela.

Exemplo de probe benigna:

```text
action_string=
```

Exemplo de payload de disponibilidade:

```text
action_string=%'; DROP TABLE access_log;--
```

Esses endpoints não são usados como probe padrão porque alteram estado do banco e podem contaminar comparações entre `rasp-on` e `rasp-off`. Para incluí-los com rigor, o ideal é executá-los como cenários separados:

- `sqli_confidentiality`: `/attack8`
- `sqli_integrity`: `/attack9`
- `sqli_availability`: `/attack10`

Sem uma probe controlada, o ZAP pode não exercitar corretamente endpoints POST como `/attack9` e `/attack10`, mesmo quando o spider roda no path pai `/SqlInjection`. A probe garante que o ZAP veja método, parâmetros, cookies e resposta real antes do active scan.

## 8. Pré-requisitos

Ambiente validado para execução local:

- Docker funcional
- Kubernetes acessível via `kubectl` (ex.: minikube)
- Python 3.9+ com `requests`

Instalação de dependência Python:

```bash
python3 -m pip install requests
```

Validação rápida:

```bash
docker version
kubectl config current-context
python3 -c "import requests; print('requests ok')"
```

## 9. Passo a Passo de Reprodução

### 9.1 Build das imagens

Execute os comandos a partir da raiz deste projeto (`sqli_rasp_experiment`), onde a pasta `rasp/` já está disponível para o `COPY` do Dockerfile.

```bash
docker build --platform linux/amd64 -t webgoat-rasp:latest -f images/webgoat-rasp/Dockerfile .
```

Se usar minikube:

```bash
minikube image load webgoat-rasp:latest
```

### 9.2 Deploy base

```bash
make deploy
make restart
make status
```

### 9.3 Execução experimental

Execução padrão focada em SQLi, comparando `rasp-on` e `rasp-off`:

```bash
make run-zap
```

Execução ampla no WebGoat root (ordem: `rasp-on,rasp-off`, com apply/restart dos perfis):

```bash
make run-zap ZAP_MODE=full
```

Execução direta do script:

```bash
sqli_rasp_experiment/scripts/rasp_toggle_experiment_zap.py
```

Execução com seleção explícita de perfis:

```bash
python3 sqli_rasp_experiment/scripts/rasp_toggle_experiment_zap.py --profiles rasp-on,rasp-off
```

### 9.4 Execução SQLi focada (cluster já em execução)

Use este modo quando a infraestrutura já está no ar e você quer rodar apenas a coleta focada em SQL Injection sem reaplicar manifests nem reiniciar deployments.

Comportamento:

- usa o estado atual do cluster (`--skip-profile-apply`)
- não faz restore/restart no final (`--skip-final-restore`)
- escaneia o path pai SQLi: `/webgoat/WebGoat/SqlInjection`

Comando:

```bash
python3 sqli_rasp_experiment/scripts/sqli_zap_current.py --mode sqli-focused
```

Opcional (ajuste de timeout):

```bash
python3 sqli_rasp_experiment/scripts/sqli_zap_current.py --mode sqli-focused --ascan-timeout 900 --spider-timeout 300
```

## 10. Artefatos e Métricas

Cada execução gera arquivos em `results/` com timestamp:

- `zap-<ts>.csv`: resumo por cenário
- `zap-<ts>.trace.log`: rastreabilidade operacional da execução
- `zap-<ts>.alerts.json`: amostras de alertas e metadados de ambiente
- `zap-<ts>.zap-alerts.json`: todos os alertas nativos retornados pela API do ZAP
- `zap-<ts>.requests.csv`: classificação por requisição observada pelo ZAP

Campos relevantes no CSV:

- `sqli_status`, `sqli_time_s`
- `detector` (`rasp|waf|none`)
- `zap_alerts_total`, `zap_alerts_sqli`
- `zap_requests_total`
- `zap_blocked_total`, `zap_blocked_rasp`, `zap_blocked_waf`
- `zap_sqli_like_total`, `zap_sqli_like_blocked`

Campos relevantes no `requests.csv`:

- `is_sqli_like`, `sqli_marker`
- `sqli_pattern_type`, `sqli_score`, `sqli_evidence`
- `layer`, `evidence`
- `request_params`, `request_body_decoded`, `response_excerpt`

## 11. Protocolo de Interpretação

Para comparação entre cenários:

1. Compare `detector` e `sqli_status` entre `rasp-on` e `rasp-off`.
2. Use `requests.csv` para inspecionar a coluna `layer` em requisições com `is_sqli_like=1`.
3. Correlacione `zap_sqli_like_blocked` com `zap_blocked_rasp` para confirmar efeito do RASP.
4. Verifique `alerts.json` para contexto de cada rodada.

## 12. Cleanup do Ambiente

### 12.1 Cleanup rápido (processos locais)

Encerra port-forward e container do ZAP usados nos runs:

```bash
pkill -f "kubectl -n sqli port-forward svc/api-gateway 18080:8080" || true
docker rm -f sqli-rasp-experiment-zap || true
```

### 12.2 Cleanup da stack do experimento no Kubernetes

Remove todos os recursos do namespace `sqli`:

```bash
kubectl delete ns sqli
```

Se quiser recriar depois:

```bash
make deploy
make restart
```

### 12.3 Cleanup completo com minikube (opcional)

Para reinício total do cluster local:

```bash
minikube stop
minikube start
minikube update-context
```

## 13. Observações de Reprodutibilidade

- O namespace Kubernetes utilizado é `sqli`.
- Ao final, o runner restaura o perfil `rasp-on`.
