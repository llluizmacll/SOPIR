# ── SOPIR API ─────────────────────────────────────────────────
FROM node:20-slim
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev
RUN npm install undici --save

COPY src ./src
COPY .env.example ./.env

ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=4s \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/api/v1/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
