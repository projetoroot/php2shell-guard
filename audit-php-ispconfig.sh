#!/bin/bash
#============================================================
# Auditoria PHP - ISPConfig
#============================================================
# Autor: Diego Costa (@diegocostaroot) / Projeto Root
# Projeto: https://github.com/projetoroot
# Versão: 1.0 - 2026
#
# DESCRIÇÃO:
# Script para auditar os sites cadastrados no ISPConfig,
# identificar o modo e a versão do PHP configurados e verificar
# referências às correções das CVE-2026-109618 e CVE-2026-109619
# nos changelogs dos pacotes PHP instalados.
#
# Verifica:
#   - Domínio, modo PHP, versão e estado no ISPConfig
#   - Evidência de correção das CVEs PHP2Shell
#   - Resumo dos sites por versão e estado das correções
#
# CVEs:
#   CVE-2026-109618
#   CVE-2026-109619
#
# FUNCIONALIDADES:
# - Lista os domínios, versões PHP e estado dos sites.
# - Verifica referências às duas CVEs nos changelogs.
# - Exibe os resultados em tabela colorida e resumo.
#
# REQUISITOS:
# - ISPConfig instalado e configurado.
# - Acesso ao banco de dados e aos pacotes PHP.
# - Execução com privilégios de root.
#
# SEGURANÇA:
# Esta ferramenta auxilia na auditoria, mas não corrige
# vulnerabilidades nem substitui atualizações de segurança.
# O resultado não garante que os serviços PHP estejam
# executando versões atualizadas. Verifique os pacotes,
# os changelogs e reinicie os serviços quando necessário.
#
#============================================================

set -eo pipefail

CONFIG="/usr/local/ispconfig/server/lib/config.inc.php"

CVE1="CVE-2026-109618"
CVE2="CVE-2026-109619"

#------------------------------------------------------------
# Configuração do ISPConfig
#------------------------------------------------------------

if [[ ! -f "$CONFIG" ]]; then
    echo "ERRO: configuração do ISPConfig não encontrada."
    exit 1
fi

DB_CONFIG=$(php -r '
include $argv[1];

foreach (["db_host", "db_database", "db_user", "db_password"] as $key) {
    if (!isset($conf[$key])) {
        fwrite(STDERR, "Configuração ausente: $key\n");
        exit(1);
    }
    echo base64_encode((string)$conf[$key]) . PHP_EOL;
}
' "$CONFIG")

mapfile -t DB <<< "$DB_CONFIG"

if [[ ${#DB[@]} -lt 4 ]]; then
    echo "ERRO: não foi possível obter as configurações do banco."
    exit 1
fi

DB_HOST=$(printf '%s' "${DB[0]}" | base64 -d)
DB_NAME=$(printf '%s' "${DB[1]}" | base64 -d)
DB_USER=$(printf '%s' "${DB[2]}" | base64 -d)
DB_PASS=$(printf '%s' "${DB[3]}" | base64 -d)

#------------------------------------------------------------
# Cores
#------------------------------------------------------------

if [[ -t 1 ]]; then
    BOLD='\033[1m'
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    RESET='\033[0m'
else
    BOLD='' GREEN='' RED='' YELLOW='' CYAN='' RESET=''
fi

#------------------------------------------------------------
# Verificar evidência de correção no changelog do pacote
#------------------------------------------------------------

verificar_cves() {
    local version="$1"
    local pkg
    local status
    local file
    local latest
    local found=0

    if [[ "$version" == "-" ||
          "$version" == "Não configurado" ||
          -z "$version" ]]; then
        printf 'N/A'
        return
    fi

    # Extrair versão principal, por exemplo PHP 8.2 -> 8.2
    version=$(printf '%s' "$version" |
        sed -nE 's/^PHP ([0-9]+\.[0-9]+)$/\1/p')

    if [[ -z "$version" ]]; then
        printf 'VERIFICAR'
        return
    fi

    pkg="php${version}-common"

    status=$(dpkg-query -W \
        -f='${db:Status-Status}' "$pkg" 2>/dev/null || true)

    if [[ "$status" != "installed" ]]; then
        printf 'NÃO INST.'
        return
    fi

    # Examinar somente a entrada mais recente do changelog.
    for file in \
        "/usr/share/doc/${pkg}/changelog.Debian.gz" \
        "/usr/share/doc/${pkg}/changelog.gz" \
        "/usr/share/doc/${pkg}/changelog.Debian" \
        "/usr/share/doc/${pkg}/changelog"; do

        [[ -f "$file" ]] || continue

        case "$file" in
            *.gz)
                latest=$(gzip -cd -- "$file" 2>/dev/null |
                    awk '{print} /^ -- / {exit}') || true
                ;;
            *)
                latest=$(awk '{print} /^ -- / {exit}' "$file") || true
                ;;
        esac

        if printf '%s\n' "$latest" |
            grep -Fq "$CVE1" &&
           printf '%s\n' "$latest" |
            grep -Fq "$CVE2"; then
            found=1
            break
        fi
    done

    if [[ "$found" -eq 1 ]]; then
        printf 'PACOTE OK'
    else
        printf 'VERIFICAR'
    fi
}

#------------------------------------------------------------
# Consulta ao ISPConfig
#------------------------------------------------------------

SQL="
SELECT
    d.domain,
    d.php,
    COALESCE(NULLIF(sp.name, ''), 'Não configurado'),
    d.active
FROM web_domain d
LEFT JOIN server_php sp
    ON sp.server_php_id = d.server_php_id
ORDER BY d.domain;
"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

if ! MYSQL_PWD="$DB_PASS" mysql \
    --host="$DB_HOST" \
    --user="$DB_USER" \
    --database="$DB_NAME" \
    --batch --skip-column-names \
    -e "$SQL" > "$TMP"; then

    echo "ERRO: falha ao consultar o banco do ISPConfig."
    exit 1
fi

#------------------------------------------------------------
# Cabeçalho
#------------------------------------------------------------

printf '\n%b============================================================%b\n' "$BOLD" "$RESET"
printf '%b                 AUDITORIA PHP - ISPCONFIG%b\n' "$BOLD" "$RESET"
printf '%b============================================================%b\n' "$BOLD" "$RESET"
printf 'Banco: %s\n' "$DB_NAME"
printf 'CVEs: %s / %s\n\n' "$CVE1" "$CVE2"

printf '%b%-3s %-29s %-14s %-20s %-14s %-10s%b\n' \
    "$BOLD" "Nº" "DOMÍNIO" "MODO PHP" "VERSÃO" \
    "CORREÇÕES CVE" "ESTADO" "$RESET"

printf '%s\n' "------------------------------------------------------------------------------------------------------"

#------------------------------------------------------------
# Contadores
#------------------------------------------------------------

TOTAL=0
ATIVOS=0
INATIVOS=0
SEM_PHP=0
NAO_CONFIG=0

CVE_OK=0
CVE_VERIFICAR=0
CVE_NAO_INST=0
CVE_NA=0

declare -A VERSOES=()

#------------------------------------------------------------
# Processar sites
#------------------------------------------------------------

while IFS=$'\t' read -r DOMAIN MODE VERSION ACTIVE; do
    [[ -z "$DOMAIN" ]] && continue

    TOTAL=$((TOTAL + 1))

    # Estado do site
    if [[ "$ACTIVE" == "y" ]]; then
        STATUS="ATIVO"
        STATUS_COLOR="$GREEN"
        ATIVOS=$((ATIVOS + 1))
    else
        STATUS="INATIVO"
        STATUS_COLOR="$RED"
        INATIVOS=$((INATIVOS + 1))
    fi

    # Interpretar modo PHP
    case "$MODE" in
        no|n)
            MODE_LABEL="sem PHP"
            MODE_COLOR="$RED"
            VERSION="-"
            SEM_PHP=$((SEM_PHP + 1))
            ;;
        y)
            MODE_LABEL="não definido"
            MODE_COLOR="$YELLOW"
            VERSION="Não configurado"
            NAO_CONFIG=$((NAO_CONFIG + 1))
            ;;
        php-fpm)
            MODE_LABEL="php-fpm"
            MODE_COLOR="$CYAN"
            ;;
        fast-cgi)
            MODE_LABEL="fast-cgi"
            MODE_COLOR="$CYAN"
            ;;
        mod)
            MODE_LABEL="mod_php"
            MODE_COLOR="$CYAN"
            ;;
        *)
            MODE_LABEL="$MODE"
            MODE_COLOR="$YELLOW"
            ;;
    esac

    # Verificar correções no pacote correspondente à versão
    CVE_STATUS=$(verificar_cves "$VERSION")

    case "$CVE_STATUS" in
        "PACOTE OK")
            CVE_COLOR="$GREEN"
            CVE_OK=$((CVE_OK + 1))
            ;;
        "VERIFICAR")
            CVE_COLOR="$YELLOW"
            CVE_VERIFICAR=$((CVE_VERIFICAR + 1))
            ;;
        "NÃO INST.")
            CVE_COLOR="$RED"
            CVE_NAO_INST=$((CVE_NAO_INST + 1))
            ;;
        *)
            CVE_COLOR="$RESET"
            CVE_NA=$((CVE_NA + 1))
            ;;
    esac

    if [[ "$VERSION" == "Não configurado" ]]; then
        VERSION_COLOR="$YELLOW"
    else
        VERSION_COLOR="$RESET"
    fi

    # Contabilizar versões, incluindo sites inativos
    if [[ "$VERSION" != "-" &&
          "$VERSION" != "Não configurado" ]]; then
        VERSOES["$VERSION"]=$(( ${VERSOES["$VERSION"]:-0} + 1 ))
    fi

    # Imprimir linha
    printf '%-3d %-29s ' "$TOTAL" "$DOMAIN"
    printf '%b%-14s%b ' "$MODE_COLOR" "$MODE_LABEL" "$RESET"
    printf '%b%-20s%b ' "$VERSION_COLOR" "$VERSION" "$RESET"
    printf '%b%-14s%b ' "$CVE_COLOR" "$CVE_STATUS" "$RESET"
    printf '%b%-10s%b\n' "$STATUS_COLOR" "$STATUS" "$RESET"

done < "$TMP"

printf '%s\n' "------------------------------------------------------------------------------------------------------"

#------------------------------------------------------------
# Resumo geral
#------------------------------------------------------------

printf '\n%bRESUMO GERAL%b\n' "$BOLD" "$RESET"
printf '%s\n' "----------------------------------------"

printf '%-30s %d\n' "Total de sites:" "$TOTAL"
printf '%b%-30s %d%b\n' "$GREEN" "Sites ativos:" "$ATIVOS" "$RESET"
printf '%b%-30s %d%b\n' "$RED" "Sites inativos:" "$INATIVOS" "$RESET"
printf '%-30s %d\n' "Sites sem PHP:" "$SEM_PHP"
printf '%-30s %d\n' "Versão não configurada:" "$NAO_CONFIG"

#------------------------------------------------------------
# Resumo das correções
#------------------------------------------------------------

printf '\n%bSTATUS DAS CORREÇÕES CVE%b\n' "$BOLD" "$RESET"
printf '%s\n' "----------------------------------------"

printf '%b%-30s %d%b\n' \
    "$GREEN" "Pacote com correções confirmadas:" "$CVE_OK" "$RESET"

printf '%b%-30s %d%b\n' \
    "$YELLOW" "Necessitam de verificação:" "$CVE_VERIFICAR" "$RESET"

printf '%b%-30s %d%b\n' \
    "$RED" "Pacote não instalado:" "$CVE_NAO_INST" "$RESET"

printf '%-30s %d\n' \
    "Não aplicável:" "$CVE_NA"

#------------------------------------------------------------
# Sites por versão
#------------------------------------------------------------

printf '\n%bSITES POR VERSÃO PHP%b\n' "$BOLD" "$RESET"
printf '%s\n' "----------------------------------------"

if [[ ${#VERSOES[@]} -gt 0 ]]; then
    while IFS= read -r VERSION; do
        [[ -z "$VERSION" ]] && continue
        printf '%b%-20s%b %d site(s)\n' \
            "$CYAN" "$VERSION" "$RESET" "${VERSOES[$VERSION]}"
    done < <(printf '%s\n' "${!VERSOES[@]}" | sort -V)
else
    printf 'Nenhuma versão PHP configurada.\n'
fi

#------------------------------------------------------------
# Finalização
#------------------------------------------------------------

printf '\n%bAuditoria concluída.%b\n' "$GREEN" "$RESET"
