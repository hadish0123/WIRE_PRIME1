FROM node:22-alpine AS build
WORKDIR /app
ARG VITE_API_BASE=/api/v1
ENV VITE_API_BASE=$VITE_API_BASE
COPY package.json .
RUN npm install --include=dev --ignore-scripts
COPY . .
# Traffic navigation must never blank the whole SPA while the traffic endpoints load.
# Keep the Traffic page rendered even if an API request is slow/unavailable.
RUN node -e "const fs=require('fs'); const p='/app/src/App.vue'; let s=fs.readFileSync(p,'utf8'); const a=s.indexOf('async function loadTrafficView(){'); const b=s.indexOf('\\nasync function load(){',a); if(a<0||b<0) throw new Error('loadTrafficView block not found'); let fn=s.slice(a,b); fn=fn.replace(' loading.value=true;\\n',''); fn=fn.replace(' }finally{loading.value=false}',' }'); fs.writeFileSync(p,s.slice(0,a)+fn+s.slice(b));"
RUN npm run typecheck && npm run build

FROM nginx:1.29-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 80
CMD ["/start.sh"]
