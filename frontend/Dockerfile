FROM node:22-alpine AS build
WORKDIR /app
ENV VITE_API_BASE=/api/v1
COPY package.json .
RUN npm install --include=dev --ignore-scripts
COPY . .
RUN npm run typecheck && npm run build

FROM nginx:1.29-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 80
CMD ["/start.sh"]
