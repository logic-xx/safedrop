FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS vendor
ARG TARGETARCH
RUN test "$TARGETARCH" = amd64
COPY deploy/scanner/fetch-vendor.mjs /fetch-vendor.mjs
RUN node /fetch-vendor.mjs && dpkg-deb -x /vendor.deb /vendor \
    && mkdir -p /runtime/bin /runtime/sbin /runtime/lib /runtime/etc/certs /runtime-data /metadata \
    && cp /vendor/usr/local/bin/freshclam /runtime/bin/ \
    && cp /vendor/usr/local/sbin/clamd /runtime/sbin/ \
    && cp -a /vendor/usr/local/lib/*.so* /runtime/lib/ \
    && cp /vendor/usr/local/etc/certs/clamav.crt /runtime/etc/certs/ \
    && dpkg-deb -f /vendor.deb | sed '/^Installed-Size:/d' > /metadata/clamav \
    && printf '\nStatus: install ok installed\n' >> /metadata/clamav

# Only signed signature data is copied from this image, never its older engine.
FROM clamav/clamav:1.5.4-debian13-slim@sha256:6982509b9e1415bf23cb49d0c55872fdd57fd2b92be33fa26d487da42d322076 AS signatures

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:6abfcb367ebc291572c774c1592a986be2ab26a2486f73093401327495a5962a
ENV TZ=Etc/UTC LD_LIBRARY_PATH=/usr/local/lib NODE_ENV=production
WORKDIR /scanner
COPY --from=vendor /runtime /usr/local
COPY --from=vendor /metadata/clamav /var/lib/dpkg/status.d/clamav
COPY deploy/scanner/LICENSES.txt /usr/share/doc/clamav/LICENSES.txt
COPY --from=vendor --chown=65532:65532 /runtime-data /data
COPY --from=signatures --chown=65532:65532 /var/lib/clamav /seed
COPY deploy/scanner/clamd.conf deploy/scanner/freshclam.conf deploy/scanner/run.mjs deploy/scanner/health.mjs ./
USER 65532:65532
EXPOSE 3310
CMD ["/scanner/run.mjs"]
