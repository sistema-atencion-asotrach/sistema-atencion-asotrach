FROM node:22-slim
WORKDIR /app
COPY package.json server.js ./
COPY lib ./lib
COPY public ./public
COPY scripts ./scripts
RUN mkdir -p /app/data && chown -R node:node /app/data
ENV NODE_ENV=production DATA_DIR=/app/data PORT=3000
VOLUME ["/app/data"]
EXPOSE 3000
USER node
CMD ["node", "server.js"]
