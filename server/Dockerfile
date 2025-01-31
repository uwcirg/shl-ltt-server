FROM denoland/deno:1.25.2
ARG APP_VERSION_STRING
ENV APP_VERSION_STRING=$APP_VERSION_STRING
EXPOSE 8000
WORKDIR /app
USER root
RUN apt-get update && \
    apt-get install -y sqlite3
USER deno
COPY  --chown=deno deps.ts .
RUN deno cache deps.ts
COPY --chown=deno . .
RUN deno cache server.ts
#TODO review logging docs RUN mkdir -p /var/tmp/log
CMD ["run", "--allow-all", "server.ts"]
