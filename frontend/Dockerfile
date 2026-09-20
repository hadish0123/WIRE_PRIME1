FROM node:22-alpine AS build
WORKDIR /app
ARG VITE_API_BASE=/api/v1
ENV VITE_API_BASE=$VITE_API_BASE
COPY package.json .
RUN npm install --include=dev --ignore-scripts
COPY . .
# Traffic navigation must never blank the whole SPA while the traffic endpoints load.
# Keep the Traffic page rendered even if an API request is slow/unavailable.
RUN python3 - <<'PY'
from pathlib import Path
p = Path("/app/src/App.vue")
s = p.read_text()
start = s.index("async function loadTrafficView(){")
end = s.index("\nasync function load(){", start)
fn = s[start:end]
fn = fn.replace(" loading.value=true;\n", "")
fn = fn.replace(" }finally{loading.value=false}", " }")
s = s[:start] + fn + s[end:]
p.write_text(s)
PY
RUN npm run typecheck && npm run build

FROM nginx:1.29-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 80
CMD ["/start.sh"]
