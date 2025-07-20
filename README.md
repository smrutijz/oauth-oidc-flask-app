# Okta OAuth OIDC App

A simple containerized app with Okta OAuth/OIDC support.

---

## 🔧 Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- Docker Compose (comes bundled with Docker Desktop)
- Internet access to pull the Docker image from Docker Hub

---

## 🧪 Running Locally (with Docker Compose)

### 1. Clone the repository
```bash
git clone https://github.com/smrutijz/okta-oauth-oidc-app.git
cd okta-oauth-oidc-app
````

### 2. Create/Add a `.env` file with proper values
refer to .env.example file

### 3. Pull and start the container

```bash
docker compose pull
docker compose up -d
```

### 4. Access the app

Open your browser at:

```
http://localhost:8080
```

---

## 🌐 Running Remotely (e.g. on VM or Cloud)

> Ensure Docker and Docker Compose are installed on the remote server.

### 1. SSH into your remote server

```bash
ssh user@your-server-ip
```

### 2. Clone the repo and navigate to it

```bash
git clone https://github.com/smrutijz/okta-oauth-oidc-app.git
cd okta-oauth-oidc-app
```

### 3. Add a `.env` file with proper values (same as above)

### 4. Start the app

```bash
docker compose pull
docker compose up -d
```

### 5. Access the app at:

```
http://<your-server-ip>:8080
```

---

## 🛑 Stopping the App

```bash
docker compose down
```

---

## 🐳 Docker Image

Pulled from Docker Hub:
`smrutijz/okta-oauth-oidc-app:latest`
