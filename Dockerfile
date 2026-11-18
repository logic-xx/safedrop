FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --cache /tmp/npm-cache
COPY . .
RUN npm run build

FROM build AS dependencies
RUN npm prune --omit=dev --ignore-scripts --cache /tmp/npm-cache && mkdir /runtime-data

# Keep package managers, shells and build dependencies out of the runtime.
# This digest is the scanned Debian 13 nonroot Node 24 image, not a floating tag.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:6abfcb367ebc291572c774c1592a986be2ab26a2486f73093401327495a5962a AS runtime
ENV NODE_ENV=production TRUST_PROXY=1 LOCAL_DIR=/data DATA_DIR=/data/store PORT=8080 PATH=/nodejs/bin:/usr/local/bin:/usr/bin:/bin
WORKDIR /app
COPY package.json package-lock.json ./
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=dependencies --chown=10001:10001 /runtime-data /data
COPY --from=build /app/build ./build
COPY --from=build /app/dist ./dist
USER 10001:10001
EXPOSE 8080
CMD ["build/server/runtime.js"]
