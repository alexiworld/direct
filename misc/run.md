# Production
npm run build && npm start

# Docker
docker build -t direct-organization-service .
docker run -p 3000:3000 direct-organization-service

# Kubernetes (with provided manifests)
kubectl apply -f deployment.yaml

# More

Next Steps:
=============
1. Ensure PostgreSQL is running
2. Run: node test-db-connection.js
3. Run: node setup-database.js (to create tables)
4. Run: ./start.sh (to start the application)
5. Test the atomic organization setup endpoint
