# Deployment Guide

This guide provides step-by-step instructions for deploying the Direct Organization Management System backend.

## Prerequisites

### System Requirements
- Node.js 18+ 
- PostgreSQL 14+
- Docker (optional, for containerized deployment)
- Redis 6+ (optional, for caching)

### Environment Setup

1. **Clone the repository:**
```bash
git clone <repository-url>
cd direct-organization-management
```

2. **Install dependencies:**
```bash
npm install
```

3. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Database Setup

### 1. Create Database
```sql
CREATE DATABASE direct_organizations;
```

### 2. Run Database Schema
Execute the SQL from `docs/03-database-schema.md`:
```bash
psql -U postgres -d direct_organizations -f docs/03-database-schema.md
```

### 3. Create Required Extensions
```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For GIN indexing
```

### 4. Set up Partitioning (Optional)
For large-scale deployments, set up partitioning for audit logs:
```sql
-- Create partitioned table for audit logs
CREATE TABLE audit_logs_partitioned (
    LIKE audit_logs INCLUDING ALL
) PARTITION BY RANGE (created_at);

-- Create partitions for each quarter
CREATE TABLE audit_logs_2026_q1 PARTITION OF audit_logs_partitioned
FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');

CREATE TABLE audit_logs_2026_q2 PARTITION OF audit_logs_partitioned
FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');
```

## Development Setup

### 1. Start Development Server
```bash
npm run dev
```

### 2. Run Tests
```bash
npm test
```

### 3. Run Linting
```bash
npm run lint
```

## Production Deployment

### Option 1: Direct Deployment

1. **Build the application:**
```bash
npm run build
```

2. **Start the server:**
```bash
npm start
```

3. **Set up process management (PM2):**
```bash
npm install -g pm2
pm2 start dist/app.js --name direct-organization-service
pm2 save
pm2 startup
```

### Option 2: Docker Deployment

1. **Build Docker image:**
```bash
docker build -t direct-organization-service .
```

2. **Run with Docker Compose:**
Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DB_HOST=postgres
      - DB_USER=postgres
      - DB_PASSWORD=password
      - DB_NAME=direct_organizations
      - REDIS_HOST=redis
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: direct_organizations
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:6-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

3. **Start services:**
```bash
docker-compose up -d
```

### Option 3: Kubernetes Deployment

1. **Create Kubernetes manifests:**
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: direct-organization-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: direct-organization-service
  template:
    metadata:
      labels:
        app: direct-organization-service
    spec:
      containers:
      - name: app
        image: direct-organization-service:latest
        ports:
        - containerPort: 3000
        env:
        - name: DB_HOST
          value: "postgres-service"
        - name: DB_USER
          value: "postgres"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        - name: DB_NAME
          value: "direct_organizations"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"

---
apiVersion: v1
kind: Service
metadata:
  name: direct-organization-service
spec:
  selector:
    app: direct-organization-service
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: LoadBalancer
```

2. **Apply manifests:**
```bash
kubectl apply -f deployment.yaml
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Server port | `3000` |
| `DB_HOST` | Database host | `localhost` |
| `DB_PORT` | Database port | `5432` |
| `DB_USER` | Database user | `postgres` |
| `DB_PASSWORD` | Database password | - |
| `DB_NAME` | Database name | `direct_organizations` |
| `DB_SSL` | Enable SSL | `false` |
| `JWT_SECRET` | JWT signing secret | - |
| `JWT_EXPIRES_IN` | JWT expiration | `24h` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `KAFKA_BROKERS` | Kafka brokers | `localhost:9092` |
| `LOG_LEVEL` | Logging level | `info` |

### Security Configuration

1. **Generate JWT Secret:**
```bash
openssl rand -base64 32
```

2. **Set up SSL/TLS for production:**
```bash
# Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

3. **Configure firewall:**
```bash
# Allow only necessary ports
ufw allow 22    # SSH
ufw allow 3000  # Application
ufw enable
```

## Monitoring and Logging

### Application Logs
```bash
# View logs
tail -f logs/app.log

# Docker logs
docker logs <container-id>

# Kubernetes logs
kubectl logs -f deployment/direct-organization-service
```

### Database Monitoring
```bash
# Monitor PostgreSQL
psql -U postgres -c "SELECT * FROM pg_stat_activity;"

# Monitor slow queries
psql -U postgres -c "SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
```

### Performance Monitoring
```bash
# Monitor application performance
pm2 monit

# Docker stats
docker stats

# Kubernetes metrics
kubectl top pods
```

## Backup and Recovery

### Database Backup
```bash
# Full backup
pg_dump -U postgres direct_organizations > backup_$(date +%Y%m%d_%H%M%S).sql

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -U postgres direct_organizations > $BACKUP_DIR/backup_$DATE.sql
gzip $BACKUP_DIR/backup_$DATE.sql
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete
```

### Application Backup
```bash
# Backup application code
tar -czf app_backup_$(date +%Y%m%d).tar.gz dist/ package.json package-lock.json

# Backup configuration
tar -czf config_backup_$(date +%Y%m%d).tar.gz .env
```

## Scaling

### Horizontal Scaling
1. **Database Read Replicas:**
```sql
-- Create read replica
CREATE REPLICATION SLOT replica_slot;
```

2. **Application Load Balancing:**
```yaml
# Nginx configuration
upstream app_servers {
    server app1:3000;
    server app2:3000;
    server app3:3000;
}

server {
    listen 80;
    location / {
        proxy_pass http://app_servers;
    }
}
```

### Vertical Scaling
1. **Increase resources:**
```yaml
# Kubernetes resource limits
resources:
  requests:
    memory: "1Gi"
    cpu: "1000m"
  limits:
    memory: "2Gi"
    cpu: "2000m"
```

## Troubleshooting

### Common Issues

1. **Database Connection Errors:**
```bash
# Check connection
psql -U postgres -h localhost direct_organizations

# Check logs
tail -f /var/log/postgresql/postgresql.log
```

2. **Permission Issues:**
```bash
# Check file permissions
ls -la dist/

# Fix permissions
chmod -R 755 dist/
```

3. **Memory Issues:**
```bash
# Check memory usage
free -h

# Increase Node.js memory
NODE_OPTIONS="--max-old-space-size=4096" npm start
```

### Health Checks

1. **Application Health:**
```bash
curl http://localhost:3000/health
```

2. **Database Health:**
```bash
psql -U postgres -c "SELECT 1;"
```

3. **Redis Health:**
```bash
redis-cli ping
```

## Security Best Practices

1. **Use HTTPS in production**
2. **Enable database SSL**
3. **Use strong passwords and secrets**
4. **Regular security updates**
5. **Network segmentation**
6. **Audit logging enabled**
7. **Regular vulnerability scanning**

## Support

For support and questions:
- Check the [README](README.md) for usage information
- Review the [API documentation](docs/04-api-structure.md)
- Check [system architecture](docs/06-system-architecture.md)

## Next Steps

After deployment:
1. Run initial data seeding
2. Configure monitoring and alerting
3. Set up automated backups
4. Implement CI/CD pipeline
5. Performance testing and optimization