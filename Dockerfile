# venenum: the Node service only. ClamAV runs beside it (compose.yaml uses the official clamav/clamav image).
FROM node:24.22.2-alpine3.24 AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --prod --ignore-scripts

FROM node:24.22.2-alpine3.24
ENV NODE_ENV=production \
    PORT=3330
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
USER node
EXPOSE 3330
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["node", "src/healthcheck.ts"]
CMD ["node", "src/main.ts"]
