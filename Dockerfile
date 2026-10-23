FROM node:20-alpine
WORKDIR /app
COPY server.js index.html data.json logo.png logo-mark.png favicon.png ./
ENV PORT=8080 DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080
CMD ["node", "server.js"]
