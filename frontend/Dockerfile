FROM node:20-alpine AS builder
WORKDIR /app

# Install deps with caching
COPY package*.json ./
RUN npm ci

# Build
COPY tsconfig*.json vite.config.ts tailwind.config.js postcss.config.js components.json index.html ./
COPY src ./src
RUN npm run build

# --- runtime: nginx serves the built static files ---
FROM nginx:1.27-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 5173
CMD ["nginx", "-g", "daemon off;"]