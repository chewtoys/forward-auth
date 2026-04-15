FROM oven/bun:1.3.12-alpine

LABEL AUTHOR mkuhlmann

WORKDIR /app
COPY --chown=bun:bun . .

# Switch to non-root user
USER bun

EXPOSE 8080
CMD ["bun", "start"]