FROM node:20-alpine
WORKDIR /app
COPY server.js index.html data.json ./
ENV PORT=8080 DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080
CMD ["node", "server.js"]
