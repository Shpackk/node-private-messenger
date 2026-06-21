FROM node:24.16.0-bookworm-slim AS build

ENV COREPACK_HOME=/corepack
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@11.6.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.base.json ./
COPY apps/api/package.json apps/api/package.json
COPY packages/contracts/package.json packages/contracts/package.json
RUN pnpm install --frozen-lockfile

COPY apps apps
COPY packages packages
RUN pnpm --filter @messenger/contracts build && pnpm --filter @messenger/api build
RUN pnpm prune --prod

FROM node:24.16.0-bookworm-slim AS runtime

ENV NODE_ENV=production
WORKDIR /app
USER node

COPY --from=build --chown=node:node /app/package.json /app/pnpm-workspace.yaml ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/apps/api/package.json ./apps/api/package.json
COPY --from=build --chown=node:node /app/apps/api/node_modules ./apps/api/node_modules
COPY --from=build --chown=node:node /app/apps/api/dist ./apps/api/dist
COPY --from=build --chown=node:node /app/packages/contracts/package.json ./packages/contracts/package.json
COPY --from=build --chown=node:node /app/packages/contracts/dist ./packages/contracts/dist

EXPOSE 3000
CMD ["node", "apps/api/dist/server.js"]
