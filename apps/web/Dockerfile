FROM node:24.21.0-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS dependencies

WORKDIR /app
ENV CI=true NX_DAEMON=false NEXT_TELEMETRY_DISABLED=1

COPY package.json package-lock.json ./
COPY apps/web/package.json ./apps/web/package.json
COPY libs/ui/package.json ./libs/ui/package.json
COPY libs/schemas/package.json ./libs/schemas/package.json
RUN npm install --global npm@11.21.0 && npm ci --include=dev --include=optional

FROM dependencies AS builder
COPY nx.json tsconfig*.json eslint.config.mjs jest.config.ts jest.preset.js ./
COPY apps/web ./apps/web
COPY libs/ui ./libs/ui
RUN npm exec -- nx run ui:typecheck --skipNxCache \
    && npm exec -- nx run web:build --skipNxCache \
    && test -f apps/web/.next/standalone/apps/web/server.js

FROM node:24.21.0-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0

# Monorepo tracing keeps the app's nested path in the standalone tree.
COPY --from=builder --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder --chown=node:node /app/apps/web/public ./apps/web/public
RUN mkdir -p apps/web/.next/cache && chown node:node apps/web/.next/cache

USER node
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
