# syntax=docker/dockerfile:1
#
# Builds the dashboard. The build context is web/dashboard:
#
#   docker build web/dashboard

ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

FROM deps AS build
ENV NEXT_TELEMETRY_DISABLED=1
COPY . .
RUN pnpm build

# The standalone output contains the server and only the node_modules it uses.
FROM node:${NODE_VERSION}-alpine
WORKDIR /app
ARG VERSION=dev
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000 \
    PF_VERSION=${VERSION}
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
USER node
EXPOSE 3000
CMD ["node", "server.js"]
