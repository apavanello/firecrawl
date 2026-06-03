#!/bin/bash
# Script para gerenciar tokens do Auth Gateway

# Auto-carregar .env do mesmo diretório do script (se existir)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
ADMIN_TOKEN="${ADMIN_TOKEN}"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para mostrar uso
show_usage() {
    echo -e "${YELLOW}Uso:${NC}"
    echo "  $0 health              - Verificar status do gateway"
    echo "  $0 list                - Listar tokens (nomes)"
    echo "  $0 create <nome>       - Criar novo token"
    echo "  $0 delete <token>      - Remover token"
    echo ""
    echo -e "${YELLOW}Variáveis de ambiente:${NC}"
    echo "  GATEWAY_URL   - URL do gateway (default: http://localhost:8080)"
    echo "  ADMIN_TOKEN   - Token de administração (obrigatório)"
}

# Verificar se ADMIN_TOKEN está setado
check_admin_token() {
    if [ -z "$ADMIN_TOKEN" ]; then
        echo -e "${RED}Erro: ADMIN_TOKEN não está setado${NC}"
        echo "Exporte a variável: export ADMIN_TOKEN=***"
        exit 1
    fi
}

# Health check
cmd_health() {
    check_admin_token
    echo -e "${GREEN}Verificando saúde do gateway...${NC}"
    curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
      "$GATEWAY_URL/admin/health" | jq .
}

# Listar tokens
cmd_list() {
    check_admin_token
    echo -e "${GREEN}Listando tokens...${NC}"
    curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
      "$GATEWAY_URL/admin/tokens" | jq .
}

# Criar token
cmd_create() {
    check_admin_token
    local name="$1"
    
    if [ -z "$name" ]; then
        echo -e "${RED}Erro: Nome do token não fornecido${NC}"
        echo "Uso: $0 create <nome>"
        exit 1
    fi
    
    echo -e "${GREEN}Criando token '$name'...${NC}"
    response=$(curl -s -X POST \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"name\": \"$name\"}" \
      "$GATEWAY_URL/admin/tokens")
    
    echo "$response" | jq .
    
    # Extrair o token
    token=$(echo "$response" | jq -r '.token')
    
    if [ "$token" != "null" ] && [ -n "$token" ]; then
        echo ""
        echo -e "${GREEN}✓ Token criado com sucesso!${NC}"
        echo -e "${YELLOW}IMPORTANTE: Salve este token, ele não será mostrado novamente:${NC}"
        echo ""
        echo -e "  ${GREEN}$token${NC}"
        echo ""
        echo "Para usar no Hermes:"
        echo "  export FIRECRAWL_API_KEY=$token"
    fi
}

# Deletar token
cmd_delete() {
    check_admin_token
    local token="$1"
    
    if [ -z "$token" ]; then
        echo -e "${RED}Erro: Token não fornecido${NC}"
        echo "Uso: $0 delete <token>"
        exit 1
    fi
    
    echo -e "${GREEN}Removendo token...${NC}"
    curl -s -X DELETE \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      "$GATEWAY_URL/admin/tokens/$token" | jq .
}

# Main
case "$1" in
    health)
        cmd_health
        ;;
    list)
        cmd_list
        ;;
    create)
        cmd_create "$2"
        ;;
    delete)
        cmd_delete "$2"
        ;;
    *)
        show_usage
        ;;
esac
