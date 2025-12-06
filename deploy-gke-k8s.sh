#!/bin/bash

# ===========================================
# Deploy postgres-mcp to GKE (gke-india cluster)
# Single script to build and deploy as standalone pod
# ===========================================

set -e

# Configuration
PROJECT_ID="ds-dev-474406"
CLUSTER_NAME="gke-india"
REGION="asia-south1"
NAMESPACE="postgres-mcp"
APP_NAME="postgres-mcp"
IMAGE_NAME="postgres-mcp"
IMAGE_TAG="latest"
GCR_IMAGE="gcr.io/$PROJECT_ID/$IMAGE_NAME:$IMAGE_TAG"
CLOUD_SQL_INSTANCE="ds-dev-474406:asia-south1:ds-dev-pg"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Header
echo ""
echo "=========================================="
echo "Deploy postgres-mcp to GKE (gke-india)"
echo "=========================================="
echo "Project: $PROJECT_ID"
echo "Cluster: $CLUSTER_NAME"
echo "Region: $REGION"
echo "Namespace: $NAMESPACE"
echo ""

# Step 1: Verify Prerequisites
log_info "Step 1: Verifying prerequisites..."
if ! command -v gcloud &> /dev/null; then
    log_error "gcloud CLI not found. Please install it."
    exit 1
fi
if ! command -v kubectl &> /dev/null; then
    log_error "kubectl not found. Please install it."
    exit 1
fi
if ! command -v docker &> /dev/null; then
    log_error "Docker not found. Please install it."
    exit 1
fi
log_success "All prerequisites available"
echo ""

# Step 2: Verify gcloud auth
log_info "Step 2: Verifying gcloud authentication..."
CURRENT_USER=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)
if [ -z "$CURRENT_USER" ]; then
    log_error "Not authenticated with gcloud. Run: gcloud auth login"
    exit 1
fi
log_success "Authenticated as: $CURRENT_USER"
echo ""

# Step 3: Verify gcloud project
log_info "Step 3: Verifying gcloud project..."
CURRENT_PROJECT=$(gcloud config get-value project)
if [ "$CURRENT_PROJECT" != "$PROJECT_ID" ]; then
    log_info "Setting project to $PROJECT_ID..."
    gcloud config set project $PROJECT_ID
fi
log_success "Using project: $PROJECT_ID"
echo ""

# Step 4: Build Docker Image
log_info "Step 4: Building Docker image..."
echo "  Building: $IMAGE_NAME:$IMAGE_TAG"
docker build -f /Users/dharsankumar/Documents/GitHub/postgres-mcp/Dockerfile.cloud-run-fixed \
    -t $IMAGE_NAME:$IMAGE_TAG \
    /Users/dharsankumar/Documents/GitHub/postgres-mcp/
log_success "Docker image built successfully"
echo ""

# Step 5: Configure Docker for GCR
log_info "Step 5: Configuring Docker for Google Container Registry..."
gcloud auth configure-docker gcr.io --quiet
log_success "Docker configured for GCR"
echo ""

# Step 6: Tag and Push to GCR
log_info "Step 6: Pushing image to GCR..."
docker tag $IMAGE_NAME:$IMAGE_TAG $GCR_IMAGE
docker push $GCR_IMAGE
log_success "Image pushed to GCR: $GCR_IMAGE"
echo ""

# Step 7: Get GKE Cluster Credentials
log_info "Step 7: Getting GKE cluster credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --region=$REGION --project=$PROJECT_ID
log_success "Cluster credentials obtained"
echo ""

# Step 8: Create Namespace
log_info "Step 8: Creating/verifying namespace..."
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
log_success "Namespace $NAMESPACE ready"
echo ""

# Step 9: Create Secret for Database URI
log_info "Step 9: Creating/updating database credential secret..."
DATABASE_URI="postgresql://django:DjangoDS20255a90dc5c95690e67@localhost:5432/topmate_db_new"
kubectl delete secret postgres-mcp-credentials -n $NAMESPACE 2>/dev/null || true
kubectl create secret generic postgres-mcp-credentials \
    --from-literal=database-url="$DATABASE_URI" \
    -n $NAMESPACE
log_success "Secret created: postgres-mcp-credentials"
echo ""

# Step 10: Deploy to GKE using kubectl
log_info "Step 10: Deploying postgres-mcp to GKE..."
cat <<EOF | kubectl apply -f -
---
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: $NAMESPACE
  name: $APP_NAME
  labels:
    app: $APP_NAME
spec:
  replicas: 2
  selector:
    matchLabels:
      app: $APP_NAME
  template:
    metadata:
      labels:
        app: $APP_NAME
    spec:
      serviceAccountName: $APP_NAME
      containers:
      # Cloud SQL Proxy sidecar
      - name: cloud-sql-proxy
        image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.19.0
        args:
          - $CLOUD_SQL_INSTANCE
          - --port=5432
          - --address=127.0.0.1
        ports:
        - containerPort: 5432
          name: postgres
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
        securityContext:
          allowPrivilegeEscalation: false

      # Main postgres-mcp container
      - name: $APP_NAME
        image: $GCR_IMAGE
        ports:
        - containerPort: 8000
          name: http
        env:
        - name: DATABASE_URI
          valueFrom:
            secretKeyRef:
              name: postgres-mcp-credentials
              key: database-url
        - name: ACCESS_MODE
          value: "restricted"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          tcpSocket:
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
        readinessProbe:
          tcpSocket:
            port: 8000
          initialDelaySeconds: 15
          periodSeconds: 5
          failureThreshold: 3

---
apiVersion: v1
kind: Service
metadata:
  namespace: $NAMESPACE
  name: $APP_NAME
  labels:
    app: $APP_NAME
spec:
  selector:
    app: $APP_NAME
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8000
    protocol: TCP
    name: http

---
apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: $NAMESPACE
  name: $APP_NAME
EOF

log_success "Deployment created"
echo ""

# Step 11: Wait for deployment to be ready
log_info "Step 11: Waiting for deployment to be ready..."
kubectl rollout status deployment/$APP_NAME -n $NAMESPACE --timeout=300s
log_success "Deployment is ready"
echo ""

# Step 12: Update Ingress to route postgres-mcp
log_info "Step 12: Adding postgres-mcp to existing Ingress..."
kubectl patch ingress topmate-dev-ingress -n default --type='json' -p='[
  {"op": "add", "path": "/spec/rules/0/http/paths/-", "value": {"path": "/postgres-mcp", "backend": {"serviceName": "'$APP_NAME'", "port": {"number": 80}}}}
]' 2>/dev/null || log_warning "Could not patch ingress automatically. Manual configuration may be needed."
echo ""

# Step 13: Get Service Info
log_info "Step 13: Service information..."
EXTERNAL_IP=$(kubectl get ingress topmate-dev-ingress -n default -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "34.49.246.87")
SERVICE_IP=$(kubectl get service $APP_NAME -n $NAMESPACE -o jsonpath='{.spec.clusterIP}')
log_success "Service deployed"
echo "  Service Name: $APP_NAME"
echo "  Namespace: $NAMESPACE"
echo "  Cluster IP: $SERVICE_IP"
echo "  External IP (via Ingress): $EXTERNAL_IP"
echo "  Public URL: http://$EXTERNAL_IP/postgres-mcp"
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}SUCCESS!${NC}"
echo "=========================================="
echo ""
echo "postgres-mcp has been deployed to gke-india"
echo ""
echo "Deployment Details:"
echo "  Cluster: $CLUSTER_NAME ($REGION)"
echo "  Namespace: $NAMESPACE"
echo "  Image: $GCR_IMAGE"
echo "  Replicas: 2"
echo ""
echo "Access:"
echo "  Service: http://$APP_NAME.$NAMESPACE.svc.cluster.local"
echo "  Via Ingress: http://$EXTERNAL_IP/postgres-mcp"
echo ""
echo "Verify Deployment:"
echo "  kubectl get deployment -n $NAMESPACE"
echo "  kubectl get pods -n $NAMESPACE"
echo "  kubectl logs -n $NAMESPACE -l app=$APP_NAME -c $APP_NAME -f"
echo ""
echo "Delete Deployment (if needed):"
echo "  kubectl delete namespace $NAMESPACE"
echo ""
