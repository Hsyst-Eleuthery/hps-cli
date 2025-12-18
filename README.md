# HPS CLI — HPS Browser em modo totalmente automatizável

Bem-vindo(a) ao **HPS CLI**, a versão **100% linha de comando** do [HPS Browser](https://github.com/Hsyst/hps) 🌐⚙️

Este projeto nasce da necessidade de usar a **rede descentralizada HPS** sem interface gráfica para realizar automatizações, permitindo **automação completa**, integração com scripts, servidores, pipelines, bots e qualquer outro sistema que precise interagir com a rede HPS de forma direta, confiável e silenciosa.

Se o HPS Browser é a porta visual da rede, o **HPS CLI é o motor invisível por trás dela**.

---

# Documentação técnica

Espera, você é desenvolvedor(a) e deseja entender mais a fundo como essa aplicação funciona? [Clique aqui!](https://github.com/Hsyst/hps-cli/blob/main/doc-tecnica.md)

## 🧠 O que é o HPS CLI?

O **HPS CLI** é um cliente oficial da rede HPS baseado no mesmo núcleo lógico do **HPS Browser**, porém adaptado para funcionar exclusivamente em terminal.

Isso significa que:

* Ele **participa da rede P2P HPS** normalmente
* Usa **criptografia, assinatura, PoW, reputação e DNS HPS**
* Faz **upload, download, busca, DNS, reports e sync**
* Tudo isso **sem depender de interface gráfica**

Na prática, ele é ideal para:

* 🤖 Automações de upload de conteúdo
* 📥 Download programático de arquivos
* 🔁 Integração com outros sistemas
* 🧪 Testes, servidores, containers, VPS
* 🛠️ Uso headless (sem TTY)
* 📡 Ferramentas que querem usar a HPS como backend

---

## 📦 Como baixar

O HPS CLI é distribuído oficialmente via **releases**:

👉 [https://github.com/Hsyst/hps-cli/releases](https://github.com/Hsyst/hps-cli/releases)

Você pode baixar:

* O código-fonte
* Pacotes prontos (quando disponíveis)

Sempre prefira a **última versão estável**.

---

## 🐍 Requisitos

Antes de começar, você precisa apenas de:

* Python **3.12 ou superior**
* pip
* Sistema Linux ou macOS (Windows funciona, mas Linux é o ambiente ideal)

---

## 🚀 Instalação

A forma mais simples (universal) é pelo python:

```
pip install aiohttp python-socketio cryptography PyYAML setproctitle
```

Na primeira execução, o cliente:

* Gera suas **chaves criptográficas**
* Cria o diretório `~/.hps_cli`
* Inicializa o banco local

Tudo de forma automática ✨

---

## 🖥️ Como rodar

Depois de instalado, basta executar:

```
python3 index.py
```

Você verá o banner do HPS CLI e já poderá usar comandos como:

* `login`
* `upload`
* `download`
* `search`
* `dns-reg`
* `dns-res`

Tudo em **modo interativo** ou **não-interativo**.

---

## 🧩 Modo Controller (Automação total)

Um dos grandes diferenciais do HPS CLI é o **controller_pipe**, que permite controlar o cliente **via arquivo**, sem stdin, sem TTY e sem dependência de sessão interativa.

Esse modo foi criado especificamente para:

* Automação
* Execução em background
* Comunicação entre processos
* Scripts externos

O funcionamento é simples e elegante:

1️⃣ Um arquivo especial recebe comandos
2️⃣ O HPS CLI detecta esse comando
3️⃣ Ele executa internamente
4️⃣ Retorna o resultado via **arquivo de log**

Esse sistema é explicado em detalhes na **Documentação Técnica**. Para saber mais [Clique aqui!](https://github.com/Hsyst/hps-cli/blob/main/doc-tecnica.md#3-controller-pipe-controllerfilemonitor)

---

## 💡 Filosofia do projeto

O HPS CLI não é apenas “um client sem interface”.

Ele foi projetado para ser:

* 🧠 Inteligente
* 🔐 Seguro
* 🧱 Resiliente
* 🔄 Automatizável
* 🌍 Um cidadão completo da rede HPS

Tudo o que o HPS Browser faz, o CLI **também faz**, apenas trocando cliques por comandos.

---

## 📚 Próximo passo

👉 Leia a [Documentação Técnica](#) para entender:

* Como funciona o controller_pipe
* Como enviar comandos
* Como interpretar logs
* Como integrar com outros sistemas

## 💡 Créditos

Feito com ❤️ pela [Thaís](https://github.com/op3ny)
, boa exploração! 🚀
