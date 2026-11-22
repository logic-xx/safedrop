FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS vendor_download
ARG REQUIRE_LOCAL_VENDOR=0
COPY deploy/scanner/fetch-vendor.mjs deploy/scanner/vendor-artifact.mjs /
RUN test "$REQUIRE_LOCAL_VENDOR" = 0 && node /fetch-vendor.mjs

# A named context of this name replaces only this public package input.
FROM scratch AS vendor_package
COPY --from=vendor_download /vendor.deb /vendor.deb

FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS vendor
ARG TARGETARCH
RUN test "$TARGETARCH" = amd64
COPY deploy/scanner/fetch-vendor.mjs deploy/scanner/vendor-artifact.mjs /
COPY --from=vendor_package /vendor.deb /vendor.deb
RUN node /fetch-vendor.mjs --verify /vendor.deb && dpkg-deb -x /vendor.deb /vendor \
    && mkdir -p /runtime/bin /runtime/sbin /runtime/lib /runtime/etc/certs /runtime-data /metadata \
    && cp /vendor/usr/local/bin/freshclam /runtime/bin/ \
    && cp /vendor/usr/local/sbin/clamd /runtime/sbin/ \
    && cp -a /vendor/usr/local/lib/*.so* /runtime/lib/ \
    && cp /vendor/usr/local/etc/certs/clamav.crt /runtime/etc/certs/ \
    && dpkg-deb -f /vendor.deb | sed '/^Installed-Size:/d' > /metadata/clamav \
    && printf '\nStatus: install ok installed\n' >> /metadata/clamav

# Only signed signature data is copied from this image, never its older engine.
FROM clamav/clamav:1.5.4-debian13-slim@sha256:6982509b9e1415bf23cb49d0c55872fdd57fd2b92be33fa26d487da42d322076 AS signatures

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:6abfcb367ebc291572c774c1592a986be2ab26a2486f73093401327495a5962a AS node_runtime

# Exact official Node/C++ files; ClamAV also needs no system OpenSSL.
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:89815d620ac01d8de13cdaf04d19ed874447ca2296d4985b14b818f6e5e47854
COPY --from=node_runtime /nodejs /nodejs
COPY --from=node_runtime /usr/lib/x86_64-linux-gnu/libstdc++.so.6* /usr/lib/x86_64-linux-gnu/
COPY --from=node_runtime /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/
COPY --from=node_runtime /var/lib/dpkg/status.d/libstdc++6 /var/lib/dpkg/status.d/libstdc++6
COPY --from=node_runtime /var/lib/dpkg/status.d/libgcc-s1 /var/lib/dpkg/status.d/libgcc-s1
COPY --from=node_runtime /var/lib/dpkg/status.d/gcc-14-base /var/lib/dpkg/status.d/gcc-14-base
COPY --from=node_runtime /usr/share/doc/gcc-14-base /usr/share/doc/gcc-14-base
COPY deploy/runtime/ /runtime/
ENV TZ=Etc/UTC LD_LIBRARY_PATH=/usr/local/lib NODE_ENV=production
WORKDIR /scanner
COPY --from=vendor /runtime /usr/local
COPY --from=vendor /metadata/clamav /var/lib/dpkg/status.d/clamav
COPY deploy/scanner/LICENSES.txt /usr/share/doc/clamav/LICENSES.txt
COPY --from=vendor --chown=65532:65532 /runtime-data /data
COPY --from=signatures --chown=65532:65532 /var/lib/clamav /seed
COPY deploy/scanner/clamd.conf deploy/scanner/freshclam.conf deploy/scanner/run.mjs deploy/scanner/health.mjs ./
COPY deploy/scanner/vendor-manifest.json ./
USER 65532:65532
RUN ["/nodejs/bin/node", "/runtime/verify.mjs"]
EXPOSE 3310
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["/scanner/run.mjs"]
