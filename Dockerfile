# syntax=docker/dockerfile:1
FROM node:20-alpine

WORKDIR /workspace

# Middleware (own node_modules — required for ../../middleware imports from backend/src)
COPY middleware/package.json middleware/package-lock.json ./middleware/
WORKDIR /workspace/middleware
RUN npm ci --omit=dev && npm cache clean --force
COPY middleware/*.js ./

# Backend API
WORKDIR /workspace/backend
COPY backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY backend/src ./src

RUN addgroup -g 1001 -S api && adduser -S api -u 1001 -G api \
  && chown -R api:api /workspace

USER api
EXPOSE 4000

CMD ["node", "src/index.js"]
