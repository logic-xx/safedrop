FROM node:24.14.0-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --cache /tmp/npm-cache
COPY . .
RUN npm run build

FROM node:24.14.0-bookworm-slim AS runtime
ENV NODE_ENV=production TRUST_PROXY=1 LOCAL_DIR=/data DATA_DIR=/data/store PORT=8080
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --cache /tmp/npm-cache && mkdir /data && chown 10001:10001 /data
COPY --from=build /app/build ./build
COPY --from=build /app/dist ./dist
USER 10001:10001
EXPOSE 8080
CMD ["sh", "-c", "node build/scripts/setup.js && exec node build/server/index.js"]
