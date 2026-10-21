# PHP2Shell Guard

Ferramenta para auditoria de versões PHP potencialmente vulneráveis e aplicação de mitigação temporária em servidores Debian e Ubuntu com Apache HTTP Server.

O PHP2Shell Guard permite verificar versões do PHP, aplicar um bloqueio temporário de requisições multipart, consultar o estado da mitigação, gerar relatórios e reverter as alterações gerenciadas pela ferramenta.

> [!WARNING]
> A mitigação não corrige o PHP nem substitui atualizações de segurança. O bloqueio de requisições multipart pode interromper uploads e outras funcionalidades legítimas das aplicações hospedadas.

## Sumário

- [Características](#características)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Verificar vulnerabilidades](#verificar-vulnerabilidades)
- [Aplicar a mitigação](#aplicar-a-mitigação)
- [Consultar o estado](#consultar-o-estado)
- [Relatórios](#relatórios)
- [Rollback](#rollback)
- [Remover o software](#remover-o-software)
- [Funcionamento](#funcionamento)
- [Limitações e segurança](#limitações-e-segurança)
- [Solução de problemas](#solução-de-problemas)

## Características

- Auditoria de versões PHP instaladas.
- Identificação de versões potencialmente vulneráveis.
- Consulta de pacotes PHP presentes no sistema.
- Mitigação temporária por meio de uma regra Apache.
- Validação da sintaxe da configuração do Apache.
- Geração de relatórios de execução.
- Consulta do estado da mitigação.
- Reversão das alterações administradas pela ferramenta.

## Requisitos

- Debian ou Ubuntu.
- Apache HTTP Server.
- PHP instalado no sistema.
- Acesso administrativo por `root` ou `sudo`.
- Pacote `.deb` disponibilizado na seção de lançamentos ou no repositório do projeto.

A compatibilidade deve ser validada conforme a versão do Apache, a distribuição Linux e o modo de execução do PHP (`mod_php` ou PHP-FPM).

## Instalação

Baixe o pacote `.deb` e execute, no diretório onde o arquivo foi salvo:

```bash
sudo apt install ./php2shell-guard_1.0.0_all.deb
```

Verifique se o executável foi instalado:

```bash
command -v php2shell-guard
```

Consulte a ajuda:

```bash
sudo php2shell-guard --help
```

A instalação do pacote não significa que o PHP foi corrigido. A ferramenta atua na auditoria e na mitigação temporária.

## Verificar vulnerabilidades

Para executar somente a auditoria, sem solicitar a aplicação da mitigação:

```bash
sudo php2shell-guard --check
```

O resultado identifica versões potencialmente vulneráveis com base nos limites de versão utilizados pelo verificador.

A ferramenta pode indicar:

- Versão potencialmente vulnerável.
- Versão dentro do limite de correção considerado.
- Resultado inconclusivo.

**Importante:** a versão do PHP, isoladamente, não confirma a vulnerabilidade. Distribuições Linux podem aplicar correções retroportadas sem alterar a versão upstream exibida.

Também pode haver diferentes instalações PHP no mesmo servidor, incluindo CLI, `mod_php` e PHP-FPM.

Consulte os avisos de segurança e as versões dos pacotes fornecidos pela distribuição antes de concluir a análise.

## Aplicar a mitigação

Para executar a verificação automática e permitir que a ferramenta aplique a mitigação quando identificar indícios de vulnerabilidade:

```bash
sudo php2shell-guard
```

O fluxo previsto é:

1. Identificar as versões PHP disponíveis para auditoria.
2. Avaliar os resultados encontrados.
3. Aplicar a mitigação temporária quando indicada.
4. Validar a configuração do Apache.
5. Registrar os resultados da execução.

Se a auditoria não indicar necessidade de mitigação, o comportamento esperado é não modificar a configuração.

Se o resultado for inconclusivo, investigue manualmente o ambiente.

### O que a mitigação faz?

A regra administrada pela ferramenta bloqueia requisições cujo cabeçalho `Content-Type` corresponda à condição multipart configurada no Apache.

Isso pode afetar:

- Upload de arquivos.
- Formulários com anexos.
- Importação de arquivos.
- Funcionalidades de aplicações que dependem de `multipart/form-data`.

A mitigação é temporária e não substitui a atualização do PHP para uma versão corrigida.

Após a aplicação, valide o funcionamento das aplicações hospedadas.

## Consultar o estado

Para consultar o estado da mitigação:

```bash
sudo php2shell-guard --status
```

A saída pode informar se a mitigação está ativa, se existe estado de rollback disponível e qual configuração Apache é administrada pela ferramenta.

Uma indicação de estado ativo não garante, por si só, que todos os VirtualHosts estejam protegidos. A cobertura depende da configuração efetivamente carregada pelo Apache.

## Relatórios

Os relatórios são armazenados no diretório:

```text
/var/log/php2shell-guard/
```

Liste os arquivos:

```bash
sudo ls -lh /var/log/php2shell-guard/
```

Consulte o relatório mais recente:

```bash
sudo ls -1t /var/log/php2shell-guard/report-*.log | head -n 1
```

Para visualizar um relatório específico:

```bash
sudo less /var/log/php2shell-guard/report-20261021-143230.log
```

Substitua o nome pelo arquivo existente no servidor.

Os relatórios auxiliam na auditoria operacional e na investigação de problemas. Eles não constituem prova definitiva de que o sistema esteja livre de vulnerabilidades.

## Rollback

Para desfazer a mitigação administrada pela ferramenta:

```bash
sudo php2shell-guard --rollback
```

O rollback deve remover a regra temporária e restaurar o estado anterior preservado pelo mecanismo de reversão.

Após executar o comando, verifique o estado:

```bash
sudo php2shell-guard --status
```

Valide a configuração Apache:

```bash
sudo apache2ctl -t
```

O resultado esperado para uma configuração válida é:

```text
Syntax OK
```

### Testar o comportamento após o rollback

O teste abaixo envia uma requisição multipart inofensiva ao site local:

```bash
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  -H 'Host: chamaosti.ucpel.edu.br' \
  -F 'teste=php2shell-guard' \
  http://127.0.0.1/
```

Altere o domínio conforme a configuração do servidor.

Com a mitigação ativa, a requisição pode retornar `403 Forbidden`. Após o rollback, o código dependerá do comportamento normal da aplicação.

O importante é verificar que o bloqueio temporário deixou de produzir a resposta. Esse teste não verifica a vulnerabilidade PHP2Shell em si.

> [!CAUTION]
> O rollback remove a proteção temporária, mas não atualiza o PHP. Se o servidor continuar vulnerável, a exposição poderá voltar.

## Remover o software

Antes de remover o pacote, consulte o estado da mitigação:

```bash
sudo php2shell-guard --status
```

Se a mitigação estiver ativa e você desejar retornar à configuração anterior, execute primeiro:

```bash
sudo php2shell-guard --rollback
```

Valide o Apache:

```bash
sudo apache2ctl -t
```

Remova o pacote:

```bash
sudo apt remove php2shell-guard
```

Para solicitar a remoção das configurações mantidas pelo gerenciador de pacotes:

```bash
sudo apt purge php2shell-guard
```

Antes de usar `purge`, verifique se os backups necessários estão preservados. Relatórios e arquivos criados pela ferramenta podem exigir remoção separada.

**A remoção do software não corrige a vulnerabilidade.** Confirme o estado do Apache e do PHP antes de encerrar o procedimento.

## Funcionamento

O PHP2Shell Guard realiza quatro atividades principais:

1. **Auditoria:** compara as versões identificadas com limites de correção conhecidos.
2. **Mitigação:** administra uma regra temporária no Apache quando a lógica de decisão indica necessidade.
3. **Registro:** gera relatórios com informações das execuções.
4. **Reversão:** disponibiliza um comando para desfazer as alterações administradas pela ferramenta.

A configuração de mitigação pode ser encontrada em:

```text
/etc/apache2/conf-available/apache-multipart-guard.conf
```

Verifique a sintaxe do Apache:

```bash
sudo apache2ctl -t
```

Consulte os VirtualHosts reconhecidos:

```bash
sudo apache2ctl -S
```

Consulte os módulos carregados:

```bash
sudo apache2ctl -M
```

Esses comandos ajudam a verificar se a configuração está habilitada e a investigar a cobertura da mitigação.

## Limitações e segurança

### A mitigação não é uma correção definitiva

A prioridade deve ser instalar as atualizações de segurança do PHP fornecidas pelo fornecedor ou pela distribuição Linux.

### Correções retroportadas

Uma versão aparentemente antiga pode conter uma correção aplicada pela distribuição. Consulte os avisos de segurança e os metadados dos pacotes antes de concluir que existe vulnerabilidade.

### Múltiplas versões PHP

O PHP CLI, o `mod_php` e os pools PHP-FPM podem utilizar versões diferentes. A auditoria de um único interpretador não garante que todos os sites estejam cobertos.

### Escopo do bloqueio

Uma regra Apache global pode afetar múltiplos VirtualHosts. Verifique o escopo real antes de utilizar a ferramenta em servidores que hospedam aplicações distintas.

### Impacto nos uploads

A mitigação pode interromper funcionalidades legítimas. Teste as aplicações e os fluxos de upload após a aplicação.

### Uso em produção

Recomenda-se testar o pacote em homologação, preservar backups e validar o rollback antes de utilizar a ferramenta em servidores críticos.

## Solução de problemas

### Aviso de hostname não resolvido

Se aparecer:

```text
sudo: não foi possível resolver máquina glpi
```

Verifique:

```bash
cat /etc/hostname
cat /etc/hosts
getent hosts "$(cat /etc/hostname)"
```

O hostname definido no sistema deve ser resolvido corretamente. Corrija as entradas necessárias em `/etc/hosts`, preservando as existentes.

### Erro na configuração do Apache

Execute:

```bash
sudo apache2ctl -t
```

Se houver erro, consulte os logs do Apache e o relatório mais recente antes de realizar alterações manuais.

### Requisição multipart retorna HTTP 403

Um `403` em uma requisição multipart de teste é compatível com o funcionamento da regra de mitigação. Ele não comprova que a vulnerabilidade foi corrigida nem que todos os VirtualHosts estão protegidos.

### Resultado inconclusivo

Verifique as versões dos pacotes PHP instalados, os módulos Apache, os serviços PHP-FPM e os avisos de segurança da distribuição.

## Aviso operacional

O PHP2Shell Guard é uma ferramenta auxiliar de auditoria e mitigação. Não garante a ausência de vulnerabilidades e não substitui atualizações de segurança, testes de segurança ou procedimentos de resposta a incidentes.

O administrador é responsável por avaliar os impactos, manter backups e confirmar a integridade dos serviços após a aplicação ou reversão da mitigação.

**Prioridade:** instalar a correção definitiva fornecida pelo fornecedor do PHP ou pela distribuição Linux utilizada.
