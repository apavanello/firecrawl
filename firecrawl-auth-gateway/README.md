# Firecrawl Auth Gateway

Gateway de autenticação Bearer Token para proteger seu Firecrawl self-hosted.

## Características

- ✅ **Tokens persistentes** - sobrevive a reinicializações do container
- ✅ **Validação Bearer Token** - protege contra acesso não autorizado
- ✅ **Endpoints de administração** - gerencie tokens via API
- ✅ **Docker-ready** - fácil de implantar no Coolify

## Quick Start

### 1. Configurar variáveis de ambiente

Crie um arquivo `.env`:

```bash
ADMI...e_gerado_aqui
```

### 2. Subir o container

```bash
docker-compose up -d
```

### 3. Gerar um token para o Hermes

```bash
# Via endpoint de administração
curl -X POST http://localhost:8080/admin/tokens \
  -H "Authorization: Bearer SEU_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "hermes"}'
```

O token será retornado **apenas uma vez**. Salve-o!

### 4. Configurar o Hermes

No `~/.hermes/.env`:

```bash
FIRECRAWL_API_KEY=***_gerado_para_hermes
```

### 5. Configurar o Caddy (Coolify)

No Caddy do Coolify, aponte o domínio `fire.pavops.net` para este container ao invés do Firecrawl diretamente.

## Endpoints de Administração

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/admin/health` | Status do gateway |
| `GET` | `/admin/tokens` | Lista tokens (nomes apenas) |
| `POST` | `/admin/tokens` | Cria novo token |
| `DELETE` | `/admin/tokens/{token}` | Remove um token |

**Todos os endpoints de admin requerem `Authorization: Bearer <ADMIN_TOKEN>`**

## Estrutura de Arquivos

```
auth-proxy/
├── auth_gateway.py      # Script principal
├── Dockerfile           # Imagem Docker
├── docker-compose.yml   # Compose para Coolify
├── README.md            # Este arquivo
└── .env                 # Variáveis de ambiente (não commitar)
```

## Fluxo de Requisições

```
Internet → Caddy (Coolify) → Auth Gateway → Firecrawl
                         │
                         ├── Valida Authorization: Bearer
                         ├── Se válido: repassa para Firecrawl
                         └── Se inválido: retorna 401/403
```

## Segurança

- **Tokens hasheados com SHA-256** - o arquivo JSON armazena apenas os hashes, nunca o token original
- **Comparação constant-time** - o token de admin usa `hmac.compare_digest` para prevenir ataques de timing
- **Limite de tamanho** - requisições com body excessivo são rejeitadas (1 KB admin, 10 MB proxy)
- **Admin protegido** por token separado
- **Logs de acesso** mostram qual token foi usado (pelo nome, não pelo valor)
- **Volume persistente** mantém tokens após restarts
- **Erros sanitizados** - detalhes internos do backend não são expostos aos clientes

## Troubleshooting

### Token não funciona

```bash
# Verificar se o gateway está rodando
curl http://localhost:8080/admin/health

# Listar tokens existentes
curl -H "Authorization: Bearer SEU_ADMIN_TOKEN" \
  http://localhost:8080/admin/tokens
```

### Container não inicia

```bash
# Ver logs
docker logs firecrawl-auth-gateway

# Verificar se a porta está livre
lsof -i :8080
```

### Firecrawl não responde

```bash
# Testar conectividade direta
curl http://localhost:3002

# Verificar se o PROXY_URL está correto
docker exec firecrawl-auth-gateway env | grep PROXY_URL
```
