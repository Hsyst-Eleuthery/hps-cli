# Documentação Técnica — HPS CLI

## 1. Visão Geral

O **HPS CLI** é um cliente de linha de comando da rede descentralizada **HPS**, criado a partir do mesmo núcleo conceitual e funcional do **HPS Browser**.

Ele compartilha:

* Protocolo de comunicação
* Modelo de segurança
* Prova de Trabalho (PoW)
* Sistema de reputação
* DNS descentralizado HPS

A principal diferença está na **forma de controle**:

* O Browser usa UI
* O CLI usa comandos e arquivos

---

## 2. Arquitetura Geral

O HPS CLI é composto por três grandes blocos:

1. **Core de Rede (HPSClientCore)**
2. **Sistema de Interface CLI**
3. **Controller de Automação por Arquivo**

Esta documentação foca especialmente no **Controller**, pois ele não existe no Browser.

---

## 3. Controller Pipe (ControllerFileMonitor)

### 3.1 Objetivo

O `controller_pipe` foi criado para permitir **controle externo total** do HPS CLI sem interação humana direta.

Ele resolve problemas como:

* Execução sem terminal
* Integração com scripts
* Automação em servidores
* Comunicação entre processos

---

### 3.2 Localização dos arquivos

Ao iniciar, o HPS CLI cria:

```
~/.hps_cli/
 ├── controller_hpscli
 ├── controller.pid
 └── logs/
```

* `controller_hpscli`: arquivo de entrada de comandos
* `logs/`: diretório onde os logs de execução são criados

---

### 3.3 Enviando comandos

Para enviar um comando ao HPS CLI:

1. Escreva o comando no arquivo `controller_hpscli`

Exemplo:

```
login localhost:8080 usuario senha
```

2. O monitor detecta a alteração (normalmente em ~1 segundo)

3. O conteúdo do arquivo é **substituído automaticamente** pelo caminho do arquivo de log, por exemplo:

```
/home/user/.hps_cli/logs/9f3c2e.log
```

---

### 3.4 Ciclo de execução

O ciclo completo é:

1. Comando escrito no controller
2. CLI detecta alteração
3. Cria um arquivo de log exclusivo
4. Atualiza o controller com o caminho do log
5. Executa o comando internamente
6. Atualiza o log com o status

---

## 4. Formato do arquivo de log

O arquivo de log segue um formato simples e previsível:

### Linha 1 — Status

* `0` → erro
* `1` → comando iniciado / em progresso

### Linha 2 — Mensagem

* Mensagem de erro
* Output do comando

### Linha 3 — Resultado final

* `1` → finalizado com sucesso
* `0` → finalizado com erro

---

### Exemplo de log bem-sucedido

```
1
Upload completed successfully
1
```

### Exemplo de erro

```
0
Login failed: invalid credentials
0
```

---

## 5. Interpretação prática

Ao integrar com outro sistema:

* Aguarde o controller apontar para um log
* Leia o log periodicamente
* Interprete:

  * `0` na primeira linha → falha imediata
  * `1` sem terceira linha → ainda executando
  * Terceira linha presente → execução finalizada

Esse modelo facilita polling simples e robusto.

---

## 6. Comandos suportados via Controller

Todos os comandos do CLI podem ser executados via controller, incluindo:

* `login`
* `upload`
* `download`
* `search`
* `dns-reg`
* `dns-res`
* `network`
* `stats`
* `report`

Eles são exatamente os mesmos comandos do modo interativo.

---

## 7. Integração com o Core

Internamente:

* O Controller utiliza os mesmos `command_handlers`
* Não há duplicação de lógica
* O estado de conexão é reaproveitado

Isso garante que:

* O comportamento é idêntico ao CLI normal
* Não há inconsistências com o Browser

---

## 8. Considerações finais

O Controller Pipe transforma o HPS CLI em um **serviço controlável externamente**, sem precisar expor API HTTP ou sockets adicionais.

Esse design mantém:

* Segurança
* Simplicidade
* Portabilidade

E permite que a rede HPS seja usada como **infraestrutura de dados descentralizada**, não apenas como aplicação.

---

Fim da documentação.
