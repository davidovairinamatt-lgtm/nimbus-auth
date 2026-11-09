FROM node:22-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV DATA_FILE=/data/db.json

COPY package.json ./
COPY server.js ./

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/api/health" >/dev/null || exit 1

CMD ["node", "server.js"]
