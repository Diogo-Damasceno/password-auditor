# password-auditor

Ferramenta de linha de comando para **auditar a qualidade de senhas** — sem
quebrar senhas de terceiros. Analisa entropia, estima tempo de quebra em vários
cenários de ataque, detecta senhas comuns/vazadas, sequências de teclado e reuso.

> Projeto educacional de cybersegurança. Use apenas em senhas próprias.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/password-auditor.git
cd password-auditor
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/pwaudit" ~/.local/bin/pwaudit
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# analisa (digite oculto se omitir o argumento)
pwaudit
pwaudit "MinhaSenha123"

# saida JSON / sem cores
pwaudit "MinhaSenha123" --json
```

## Licença

MIT — veja `LICENSE`.
