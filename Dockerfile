# ── SOPIR · frontend ─────────────────────────────────────────
# Build da aplicação React + Vite
FROM node:20-alpine AS build
WORKDIR /app

# Base da API usada pelo frontend em runtime (via proxy do nginx)
ARG VITE_API_BASE=/api/v1
ENV VITE_API_BASE=${VITE_API_BASE}

COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Serve o build estático com nginx (também faz proxy de /api → sopir-api)
FROM nginx:1.27-alpine
# curl instalado explicitamente pro HEALTHCHECK — não depender do que a
# imagem base do nginx:alpine trouxer (varia por build, causava "unhealthy"
# mesmo com o nginx respondendo normal, porque o wget não existia)
RUN apk add --no-cache curl
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost/ >/dev/null || exit 1
CMD ["nginx", "-g", "daemon off;"]
