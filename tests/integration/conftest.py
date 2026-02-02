"""Fixtures for integration tests that run against a real Kubernetes cluster."""

import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output


MANIFESTS_DIR = Path(__file__).parent / "manifests"


def kubectl(*args, check=True, capture_output=True, input=None):
    """Run kubectl command and return result."""
    cmd = ["kubectl"] + list(args)
    return subprocess.run(cmd, capture_output=capture_output, text=True, check=check, input=input)


def wait_for_condition(check_fn, timeout=60, interval=2):
    """Wait for a condition to be true."""
    start = time.time()
    while time.time() - start < timeout:
        if check_fn():
            return True
        time.sleep(interval)
    return False


@pytest.fixture(scope="session")
def cluster_available():
    """Check if a Kubernetes cluster is available.

    This fixture runs before all integration tests and skips them
    if no cluster is accessible or kubectl is not installed.
    """
    try:
        result = subprocess.run(
            ["kubectl", "cluster-info"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.skip("Kubernetes cluster not available")
    except FileNotFoundError:
        pytest.skip("kubectl not installed")
    return True


@pytest.fixture(scope="session")
def test_namespace(cluster_available):
    """Create an isolated namespace for integration tests.

    The namespace is created once per test session and cleaned up afterward.
    """
    ns = f"boxctl-test-{uuid.uuid4().hex[:8]}"
    kubectl("create", "namespace", ns)
    yield ns
    # Cleanup - don't wait for deletion to complete
    kubectl("delete", "namespace", ns, "--wait=false", check=False)


@pytest.fixture
def real_context(cluster_available):
    """Provide a real Context for running scripts against the cluster."""
    return Context()


@pytest.fixture
def output():
    """Provide a fresh Output instance."""
    return Output()


# --- Resource Creation Helpers ---

@pytest.fixture
def healthy_pod(test_namespace):
    """Create a healthy running pod."""
    name = f"healthy-pod-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    app: {name}
    test: integration
spec:
  containers:
  - name: main
    image: busybox:1.36
    command: ["sleep", "3600"]
    resources:
      requests:
        memory: "32Mi"
        cpu: "10m"
      limits:
        memory: "64Mi"
        cpu: "50m"
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)

    # Wait for pod to be running
    def is_running():
        result = kubectl("get", "pod", name, "-n", test_namespace, "-o", "jsonpath={.status.phase}")
        return result.stdout.strip() == "Running"

    if not wait_for_condition(is_running, timeout=60):
        pytest.fail(f"Pod {name} did not become Running within timeout")

    yield name
    kubectl("delete", "pod", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def pending_pod(test_namespace):
    """Create a pod that will stay in Pending state (unschedulable)."""
    name = f"pending-pod-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    app: {name}
    test: integration
spec:
  containers:
  - name: main
    image: busybox:1.36
    command: ["sleep", "3600"]
    resources:
      requests:
        memory: "999Gi"
        cpu: "999"
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)

    # Give it a moment to be created
    time.sleep(2)

    yield name
    kubectl("delete", "pod", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def healthy_deployment(test_namespace):
    """Create a healthy deployment with all replicas ready."""
    name = f"healthy-deploy-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    app: {name}
    test: integration
spec:
  replicas: 2
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
      - name: main
        image: busybox:1.36
        command: ["sleep", "3600"]
        resources:
          requests:
            memory: "32Mi"
            cpu: "10m"
          limits:
            memory: "64Mi"
            cpu: "50m"
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)

    # Wait for deployment to be ready
    def is_ready():
        result = kubectl(
            "get", "deployment", name, "-n", test_namespace,
            "-o", "jsonpath={.status.readyReplicas}"
        )
        try:
            return int(result.stdout.strip() or "0") >= 2
        except ValueError:
            return False

    if not wait_for_condition(is_ready, timeout=120):
        pytest.fail(f"Deployment {name} did not become ready within timeout")

    yield name
    kubectl("delete", "deployment", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def unhealthy_deployment(test_namespace):
    """Create a deployment that cannot reach desired replicas."""
    name = f"unhealthy-deploy-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    app: {name}
    test: integration
spec:
  replicas: 3
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
      - name: main
        image: busybox:1.36
        command: ["sleep", "3600"]
        resources:
          requests:
            memory: "999Gi"
            cpu: "999"
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)

    # Give it time to try scheduling
    time.sleep(5)

    yield name
    kubectl("delete", "deployment", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def healthy_service(test_namespace, healthy_deployment):
    """Create a service with matching endpoints."""
    name = f"healthy-svc-{uuid.uuid4().hex[:6]}"
    # Extract the app label from the deployment name
    app_label = healthy_deployment
    manifest = f"""
apiVersion: v1
kind: Service
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    test: integration
spec:
  selector:
    app: {app_label}
  ports:
  - port: 80
    targetPort: 8080
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)

    # Wait for endpoints to be populated
    def has_endpoints():
        result = kubectl(
            "get", "endpoints", name, "-n", test_namespace,
            "-o", "jsonpath={.subsets[*].addresses[*].ip}"
        )
        return bool(result.stdout.strip())

    if not wait_for_condition(has_endpoints, timeout=30):
        pytest.fail(f"Service {name} has no endpoints within timeout")

    yield name
    kubectl("delete", "service", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def service_no_endpoints(test_namespace):
    """Create a service with no matching pods (selector mismatch)."""
    name = f"no-endpoints-svc-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: v1
kind: Service
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    test: integration
spec:
  selector:
    app: nonexistent-app-{uuid.uuid4().hex[:6]}
  ports:
  - port: 80
    targetPort: 8080
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)
    time.sleep(2)

    yield name
    kubectl("delete", "service", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def healthy_statefulset(test_namespace):
    """Create a healthy StatefulSet."""
    name = f"healthy-sts-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    app: {name}
    test: integration
spec:
  serviceName: {name}
  replicas: 1
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
      - name: main
        image: busybox:1.36
        command: ["sleep", "3600"]
        resources:
          requests:
            memory: "32Mi"
            cpu: "10m"
          limits:
            memory: "64Mi"
            cpu: "50m"
"""
    # Create headless service for StatefulSet
    svc_manifest = f"""
apiVersion: v1
kind: Service
metadata:
  name: {name}
  namespace: {test_namespace}
spec:
  clusterIP: None
  selector:
    app: {name}
  ports:
  - port: 80
"""
    kubectl("apply", "-f", "-", input=svc_manifest, capture_output=False, check=True)
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)

    # Wait for statefulset to be ready
    def is_ready():
        result = kubectl(
            "get", "statefulset", name, "-n", test_namespace,
            "-o", "jsonpath={.status.readyReplicas}"
        )
        try:
            return int(result.stdout.strip() or "0") >= 1
        except ValueError:
            return False

    if not wait_for_condition(is_ready, timeout=120):
        pytest.fail(f"StatefulSet {name} did not become ready within timeout")

    yield name
    kubectl("delete", "statefulset", name, "-n", test_namespace, "--wait=false", check=False)
    kubectl("delete", "service", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def completed_job(test_namespace):
    """Create a job that completes successfully."""
    name = f"completed-job-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: batch/v1
kind: Job
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    test: integration
spec:
  template:
    spec:
      containers:
      - name: main
        image: busybox:1.36
        command: ["echo", "success"]
      restartPolicy: Never
  backoffLimit: 1
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)

    # Wait for job to complete
    def is_complete():
        result = kubectl(
            "get", "job", name, "-n", test_namespace,
            "-o", "jsonpath={.status.succeeded}"
        )
        try:
            return int(result.stdout.strip() or "0") >= 1
        except ValueError:
            return False

    if not wait_for_condition(is_complete, timeout=60):
        pytest.fail(f"Job {name} did not complete within timeout")

    yield name
    kubectl("delete", "job", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def failed_job(test_namespace):
    """Create a job that fails."""
    name = f"failed-job-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: batch/v1
kind: Job
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    test: integration
spec:
  template:
    spec:
      containers:
      - name: main
        image: busybox:1.36
        command: ["false"]
      restartPolicy: Never
  backoffLimit: 0
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)

    # Wait for job to fail
    def is_failed():
        result = kubectl(
            "get", "job", name, "-n", test_namespace,
            "-o", "jsonpath={.status.failed}"
        )
        try:
            return int(result.stdout.strip() or "0") >= 1
        except ValueError:
            return False

    if not wait_for_condition(is_failed, timeout=60):
        pytest.fail(f"Job {name} did not fail within timeout")

    yield name
    kubectl("delete", "job", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def resource_quota(test_namespace):
    """Create a resource quota in the test namespace."""
    name = f"test-quota-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: v1
kind: ResourceQuota
metadata:
  name: {name}
  namespace: {test_namespace}
spec:
  hard:
    pods: "10"
    requests.cpu: "2"
    requests.memory: "2Gi"
    limits.cpu: "4"
    limits.memory: "4Gi"
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)
    time.sleep(2)

    yield name
    kubectl("delete", "resourcequota", name, "-n", test_namespace, "--wait=false", check=False)


@pytest.fixture
def pvc_pending(test_namespace):
    """Create a PVC that will stay pending (no matching PV)."""
    name = f"pending-pvc-{uuid.uuid4().hex[:6]}"
    manifest = f"""
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {name}
  namespace: {test_namespace}
  labels:
    test: integration
spec:
  accessModes:
  - ReadWriteOnce
  storageClassName: nonexistent-storage-class-{uuid.uuid4().hex[:6]}
  resources:
    requests:
      storage: 1Gi
"""
    kubectl("apply", "-f", "-", input=manifest, capture_output=False, check=True)
    time.sleep(2)

    yield name
    kubectl("delete", "pvc", name, "-n", test_namespace, "--wait=false", check=False)
