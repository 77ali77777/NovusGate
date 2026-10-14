FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN npm run build

FROM nginx:alpine

# Install openssl for certificate generation
RUN apk add --no-cache openssl

# Copy built files
COPY --from=builder /app/dist /usr/share/nginx/html

# nginx config template (the image renders it into conf.d at start)
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
ENV NOVUSGATE_API_KEY=""

# Generate self-signed certificate at build time
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/C=AZ/ST=Baku/L=Baku/O=NovusGate/CN=NovusGate.local"

EXPOSE 3007

CMD ["nginx", "-g", "daemon off;"]
