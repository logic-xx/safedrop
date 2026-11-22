FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --cache /tmp/npm-cache
COPY . .
RUN npm run build

FROM build AS dependencies
RUN npm prune --omit=dev --ignore-scripts --cache /tmp/npm-cache && mkdir /runtime-data

# Keep the exact official Node binary; it statically links its own TLS library.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:6abfcb367ebc291572c774c1592a986be2ab26a2486f73093401327495a5962a AS node_runtime

# No unused system OpenSSL, shell or package manager in the final image.
# Retain package inventory/licenses for every copied C++ runtime component.
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:89815d620ac01d8de13cdaf04d19ed874447ca2296d4985b14b818f6e5e47854 AS runtime
COPY --from=node_runtime /nodejs /nodejs
COPY --from=node_runtime /usr/lib/x86_64-linux-gnu/libstdc++.so.6* /usr/lib/x86_64-linux-gnu/
COPY --from=node_runtime /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/
COPY --from=node_runtime /var/lib/dpkg/status.d/libstdc++6 /var/lib/dpkg/status.d/libstdc++6
COPY --from=node_runtime /var/lib/dpkg/status.d/libgcc-s1 /var/lib/dpkg/status.d/libgcc-s1
COPY --from=node_runtime /var/lib/dpkg/status.d/gcc-14-base /var/lib/dpkg/status.d/gcc-14-base
COPY --from=node_runtime /usr/share/doc/gcc-14-base /usr/share/doc/gcc-14-base
COPY deploy/runtime/ /runtime/
ENV NODE_ENV=production TRUST_PROXY=1 LOCAL_DIR=/data DATA_DIR=/data/store PORT=8080 PATH=/nodejs/bin:/usr/local/bin:/usr/bin:/bin
WORKDIR /app
COPY package.json package-lock.json ./
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=dependencies --chown=10001:10001 /runtime-data /data
COPY --from=build /app/build ./build
COPY --from=build /app/dist ./dist
USER 10001:10001
RUN ["/nodejs/bin/node", "/runtime/verify.mjs"]
EXPOSE 8080
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["build/server/runtime.js"]
