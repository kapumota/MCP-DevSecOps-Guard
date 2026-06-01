### Hardening Kubernetes

El manifiesto `k8s/deployment.yaml` activa controles mínimos de preproducción:

- `runAsNonRoot: true`;
- `allowPrivilegeEscalation: false`;
- `readOnlyRootFilesystem: true`;
- `capabilities.drop: ALL`;
- `seccompProfile: RuntimeDefault`;
- límites de CPU/memoria;
- probes `/ready` y `/health`;
- `NetworkPolicy` restrictiva.

Estos controles reducen privilegios del contenedor, pero no reemplazan pruebas de despliegue real ni revisión de plataforma.
