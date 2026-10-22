#!/bin/bash
#
#==========================================
# Gerenciador multipart - ISPConfig
#==========================================
# Autor: Diego Costa (@diegocostaroot) / Projeto Root (youtube.com/projetoroot)     
# Versão: 1.0
# Veja o link: https://github.com/projetoroot 
# 2026                                                        
#
# DESCRIÇÃO:
# Script interativo para gerenciar o bloqueio e a liberação de
# sites hospedados em um servidor ISPConfig, utilizando o
# ispconfig-multipart-guard.
#
# O script permite selecionar domínios individualmente ou executar
# operações em lote para todos os sites identificados.
#
# FUNCIONALIDADES:
#
# - Lista os domínios e exibe o estado atual de proteção.
# - Permite bloquear um site individualmente.
# - Permite liberar um site individualmente.
# - Permite bloquear todos os sites por meio da opção 99.
# - Permite liberar todos os sites por meio da opção 99.
# - Solicita confirmação antes de executar operações em lote.
# - Verifica o estado do bloqueio após cada operação.
# - Preserva o bloqueio do painel ISPConfig durante a liberação
#   em lote, conforme a lógica implementada no script.
#
# REQUISITOS:
#
# - ISPConfig instalado e configurado.
# - ispconfig-multipart-guard instalado. (https://www.ispconfig.org/blog/php2shell-critical-php-vulnerabilities-cve-2026-109618-cve-2026-109619/)
# - Execução com privilégios de root.
#
# COMO EXECUTAR:
#
#   chmod +x /bin/multipart-ispconfig.sh
#   /bin/multipart-ispconfig.sh
#
# EXEMPLO DO MENU:
#
#==========================================
# Gerenciador multipart - ISPConfig
#==========================================
#
# 1. Selecione o site:
#
# 1) lojaexemplo.com.br                     [BLOQUEADO]
# 2) escritorioalfa.com.br                  [BLOQUEADO]
# 3) consultoriaexemplo.com.br              [BLOQUEADO]
#
# 99) Todos os sites                        [TODOS OS SITES]
#
# Número do site (0 para sair):
#
# SEGURANÇA:
#
# Esta ferramenta aplica uma medida de mitigação por meio do
# ispconfig-multipart-guard. Ela não corrige a vulnerabilidade
# no PHP nem substitui a instalação das atualizações de segurança.
#
# O bloqueio pode afetar funcionalidades que dependam de uploads
# ou de requisições multipart/form-data. Valide o comportamento
# dos sites após aplicar alterações.
#
# Utilize primeiro em ambiente de teste, sempre que possível.
#
#==========================================

set -Eeuo pipefail

GUARD="ispconfig-multipart-guard"
TARGETS_FILE="/etc/ispconfig-multipart-guard/targets"

if [[ $EUID -ne 0 ]]; then
    echo "ERRO: execute este script como root."
    exit 1
fi

if ! command -v "$GUARD" >/dev/null 2>&1; then
    echo "ERRO: comando '$GUARD' não encontrado."
    exit 1
fi

# --------------------------------------------------
# Consulta os sites
# --------------------------------------------------

consultar_sites() {
    "$GUARD" sites
}

estado_site() {
    local dominio="$1"
    local saida

    if ! saida="$(consultar_sites)"; then
        echo "ERRO: não foi possível consultar os sites." >&2
        return 1
    fi

    printf '%s\n' "$saida" |
        awk -v d="$dominio" '
            $2 == "site" {
                for (i = 5; i <= NF; i++) {
                    if ($i == d) {
                        encontrado = 1
                        if ($3 == "yes")
                            bloqueado = 1
                    }
                }
            }
            END {
                if (!encontrado)
                    print "DESCONHECIDO"
                else if (bloqueado)
                    print "BLOQUEADO"
                else
                    print "LIBERADO"
            }
        '
}

# --------------------------------------------------
# Carrega os domínios
# --------------------------------------------------

carregar_dominios() {
    local saida

    if ! saida="$(consultar_sites)"; then
        echo "ERRO: falha ao consultar os sites do guard." >&2
        return 1
    fi

    mapfile -t DOMINIOS < <(
        printf '%s\n' "$saida" |
            awk '
                $2 == "site" {
                    for (i = 5; i <= NF; i++) {
                        if ($i !~ /^www\./ && $i !~ /^\*\./)
                            print $i
                    }
                }
            ' |
            sort -u
    )

    if [[ ${#DOMINIOS[@]} -eq 0 ]]; then
        echo "ERRO: nenhum site encontrado." >&2
        return 1
    fi
}

# --------------------------------------------------
# Confirmação
# --------------------------------------------------

confirmar_acao() {
    local mensagem="$1"
    local resposta

    echo
    read -rp "$mensagem [s/N] " resposta

    case "$resposta" in
        s|S|sim|SIM|Sim)
            return 0
            ;;
        *)
            echo "Operação cancelada."
            return 1
            ;;
    esac
}

# --------------------------------------------------
# Executa ação e confirma o estado
# --------------------------------------------------

aplicar_acao() {
    local dominio="$1"
    local comando="$2"
    local esperado="$3"
    local codigo_saida
    local novo_estado

    echo
    echo "------------------------------------------"
    echo "Site: $dominio"
    echo "Ação: $comando"
    echo "------------------------------------------"

    set +e
    "$GUARD" "$comando" "$dominio"
    codigo_saida=$?
    set -e

    echo
    echo "Código de saída do guard: $codigo_saida"

    if ! novo_estado="$(estado_site "$dominio")"; then
        echo "ERRO: não foi possível consultar o estado."
        return 1
    fi

    echo "Estado esperado: $esperado"
    echo "Estado encontrado: $novo_estado"

    if [[ "$novo_estado" != "$esperado" ]]; then
        echo "ERRO: estado diferente do esperado."
        return 1
    fi

    if (( codigo_saida != 0 )); then
        echo "AVISO: estado confirmado, mas o guard retornou erro."
        echo "Verifique os avisos e os testes automáticos."
        return 2
    fi

    echo "SUCESSO: estado confirmado."
    return 0
}

# --------------------------------------------------
# Processa todos os sites
# --------------------------------------------------

processar_todos() {
    local comando="$1"
    local esperado="$2"
    local dominio
    local resultado
    local total=0
    local confirmados=0
    local avisos=0
    local falhas=0
    local codigo_saida

    echo
    echo "=========================================="
    echo " OPERAÇÃO EM TODOS OS SITES"
    echo "=========================================="
    echo "Ação: $comando"
    echo "Total de sites: ${#DOMINIOS[@]}"
    echo
    echo "A operação será executada individualmente."
    echo "O alvo global 'all' não será usado para bloquear."
    echo "O painel do ISPConfig deve permanecer protegido."

    if ! confirmar_acao "Confirma a operação em TODOS os sites?"; then
        return 0
    fi

    # Para liberar todos, remover eventual alvo global.
    # Depois garantir que o painel continue bloqueado.
    if [[ "$comando" == "unblock" ]] &&
       [[ -f "$TARGETS_FILE" ]] &&
       grep -Eq '^[[:space:]]*all([[:space:]]|$)' "$TARGETS_FILE"; then

        echo
        echo "Alvo global 'all' detectado."
        echo "Removendo o bloqueio global..."

        set +e
        "$GUARD" unblock all
        codigo_saida=$?
        set -e

        if (( codigo_saida != 0 )); then
            echo "ERRO: não foi possível remover o alvo global."
            return 1
        fi

        echo "Garantindo o bloqueio do painel..."

        set +e
        "$GUARD" block panel
        codigo_saida=$?
        set -e

        if (( codigo_saida != 0 )); then
            echo "ERRO: não foi possível configurar a proteção do painel."
            return 1
        fi
    fi

    for dominio in "${DOMINIOS[@]}"; do
        total=$((total + 1))

        set +e
        aplicar_acao "$dominio" "$comando" "$esperado"
        resultado=$?
        set -e

        case "$resultado" in
            0)
                confirmados=$((confirmados + 1))
                ;;
            2)
                confirmados=$((confirmados + 1))
                avisos=$((avisos + 1))
                ;;
            *)
                falhas=$((falhas + 1))
                ;;
        esac
    done

    echo
    echo "=========================================="
    echo " RESUMO"
    echo "=========================================="
    echo "Ação:                  $comando"
    echo "Sites processados:     $total"
    echo "Estados confirmados:   $confirmados"
    echo "Avisos do guard:       $avisos"
    echo "Falhas de verificação: $falhas"
    echo "=========================================="

    if (( falhas > 0 )); then
        echo "ATENÇÃO: verifique os sites com falha."
        return 1
    fi

    if (( avisos > 0 )); then
        echo "ATENÇÃO: estados confirmados, mas houve avisos."
        return 2
    fi

    echo "SUCESSO: todos os estados foram confirmados."
    return 0
}

# --------------------------------------------------
# Menu principal: sites + opção 99
# --------------------------------------------------

echo "=========================================="
echo "  🔧 Diego Costa (IT Security)"
echo "  https://github.com/projetoroot"
echo " Gerenciador multipart - ISPConfig"
echo "=========================================="
echo

if ! carregar_dominios; then
    exit 1
fi

echo "1. Selecione o site:"
echo

for i in "${!DOMINIOS[@]}"; do
    dominio="${DOMINIOS[$i]}"

    if ! estado="$(estado_site "$dominio")"; then
        estado="DESCONHECIDO"
    fi

    printf "%2d) %-38s [%s]\n" \
        "$((i + 1))" "$dominio" "$estado"
done

echo
printf "99) %-38s [TODOS OS SITES]\n" "Todos os sites"
echo

read -rp "Número do site (0 para sair): " escolha

if [[ ! "$escolha" =~ ^[0-9]+$ ]]; then
    echo "ERRO: informe um número válido."
    exit 1
fi

if (( escolha == 0 )); then
    echo "Operação encerrada."
    exit 0
fi

# --------------------------------------------------
# Opção 99: todos os sites
# --------------------------------------------------

if (( escolha == 99 )); then
    echo
    echo "=========================================="
    echo " Todos os sites"
    echo "=========================================="
    echo "1) Bloquear todos os sites"
    echo "2) Liberar todos os sites"
    echo "0) Cancelar"
    echo

    read -rp "Escolha a operação: " acao

    case "$acao" in
        1)
            COMANDO="block"
            ESPERADO="BLOQUEADO"
            ;;
        2)
            COMANDO="unblock"
            ESPERADO="LIBERADO"
            ;;
        0)
            echo "Operação cancelada."
            exit 0
            ;;
        *)
            echo "ERRO: opção inválida."
            exit 1
            ;;
    esac

    if processar_todos "$COMANDO" "$ESPERADO"; then
        exit 0
    else
        resultado=$?
        exit "$resultado"
    fi
fi

# --------------------------------------------------
# Operação individual
# --------------------------------------------------

if (( escolha < 1 || escolha > ${#DOMINIOS[@]} )); then
    echo "ERRO: número de site inválido."
    exit 1
fi

DOMINIO="${DOMINIOS[$((escolha - 1))]}"

echo
echo "Site: $DOMINIO"
echo
echo "1) Bloquear"
echo "2) Liberar"
echo "0) Cancelar"
echo

read -rp "Opção: " acao

case "$acao" in
    1)
        COMANDO="block"
        ESPERADO="BLOQUEADO"
        ;;
    2)
        COMANDO="unblock"
        ESPERADO="LIBERADO"
        ;;
    0)
        echo "Operação cancelada."
        exit 0
        ;;
    *)
        echo "ERRO: opção inválida."
        exit 1
        ;;
esac

echo
echo "Site: $DOMINIO"
echo "Ação: $COMANDO"

if ! confirmar_acao "Confirma a operação?"; then
    exit 0
fi

set +e
aplicar_acao "$DOMINIO" "$COMANDO" "$ESPERADO"
resultado=$?
set -e

case "$resultado" in
    0)
        echo "Operação concluída."
        exit 0
        ;;
    2)
        echo "Estado confirmado, mas houve aviso do guard."
        exit 2
        ;;
    *)
        echo "ERRO: não foi possível confirmar a operação."
        exit 1
        ;;
esac
