FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY public ./public
COPY scripts ./scripts
COPY tests ./tests
COPY vendor ./vendor
EXPOSE 3000
CMD ["node", "server.js"]
