FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src
COPY scripts ./scripts

COPY middleware /middleware

RUN addgroup -g 1001 -S api && adduser -S api -u 1001 -G api \
    && chown -R api:api /app /middleware
USER api

EXPOSE 8080
CMD ["node", "src/index.js"]
