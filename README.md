# Password Auditor

Ferramenta de linha de comando para **auditar a qualidade de senhas** — sem quebrar senhas de terceiros. Analisa entropia, estima tempo de quebra em vários cenários de ataque, detecta senhas comuns/vazadas, sequências de teclado e reuso, e sugere melhorias.

> Projeto educacional de cybersegurança. Use apenas em senhas próprias.

## Recursos

- Cálculo de **entropia** (Shannon + espaço de busca, medida conservadora)
- **Tempo estimado de quebra** em 4 cenários (online com/sem rate-limit, offline bcrypt, offline MD5 em GPU)
- Detecção de **senhas comuns** (amostra de wordlist)
- Detecção de **sequências de teclado** e repetições
- Detecção de **reuso** entre senhas (via hash, nunca compara texto puro)
- **Sugestões** acionáveis de melhoria
- Saída colorida no terminal ou em **JSON**

## Instalação

```bash
git clone https://github.com/Diogo-Damasceno/password-auditor.git
cd password-auditor
pip install -e .
```

## Uso

```bash
# modo interativo (senha oculta, recomendado)
pwaudit

# passando direto (cuidado: fica no histórico do shell)
pwaudit 'MinhaSenha123!'

# saída JSON
pwaudit --json 'MinhaSenha123!'

# sem cores
pwaudit --plain 'MinhaSenha123!'
```

### Exemplo de saída

```
Senha:        M**********!
Comprimento:  12
Charset:      95 símbolos possíveis
Entropia:     78.9 bits
Força:        Forte [3/4] ▅▅▅▅

Tempo estimado para quebra:
  Online (limitado, 100/s):   1.23e+15 séculos
  Offline (MD5 em GPU):       12.5 anos
```

## Testes

```bash
pip install -e '.[dev]'
pytest -q
```

## Como funciona

A entropia é estimada de forma conservadora tomando o mínimo entre:

- **Espaço de busca**: `comprimento × log2(tamanho_do_charset)`
- **Shannon** ajustada pela distribuição real dos caracteres

Sequências e senhas comuns aplicam penalidades ao score final (0–4).

## Aviso legal

Ferramenta para fins **educacionais e defensivos**. Analise apenas senhas que você tem autorização para testar.

## Licença

MIT
