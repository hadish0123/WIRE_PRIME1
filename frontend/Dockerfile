FROM node:22-alpine AS build
WORKDIR /app
ARG VITE_API_BASE=/api/v1
ENV VITE_API_BASE=$VITE_API_BASE
COPY package.json .
RUN npm install --include=dev --ignore-scripts
COPY . .
RUN npm run typecheck && npm run build
FROM nginx:1.29-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
