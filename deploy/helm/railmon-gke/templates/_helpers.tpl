{{/* The scan-sidecar image, for all three containers. */}}
{{- define "railmon-gke.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "railmon-gke.labels" -}}
app.kubernetes.io/part-of: railmon
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "railmon-gke.required" -}}
{{- $_ := required "clusterName is required: the host_id this cluster's sidecars report under" .Values.clusterName -}}
{{- $_ := required "gkeScan.centerUrl is required: Rail Center's URL" .Values.gkeScan.centerUrl -}}
{{- if not .Values.enrolledNamespaces -}}
{{- fail "enrolledNamespaces is required: the namespaces whose labeled pods get the scan sidecar" -}}
{{- end -}}
{{- if has .Release.Namespace .Values.enrolledNamespaces -}}
{{- fail (printf "enrolledNamespaces can't include %s, the chart's own namespace" .Release.Namespace) -}}
{{- end -}}
{{- end -}}

{{/* gke-scan's in-cluster URL: what the sidecar posts to. */}}
{{- define "railmon-gke.gkeScanUrl" -}}
https://gke-scan.{{ .Release.Namespace }}.svc
{{- end -}}

{{/* Pod security for the chart's own containers (gke-scan, the webhook). */}}
{{- define "railmon-gke.containerSecurity" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
The one sidecar spec (the sidecar design's Container spec), which the webhook
reads from the rail-scan-sidecar-spec ConfigMap. The webhook adds, per pod:
the agent's config mounts and --config-path, runAsUser, runAsGroup and
runAsNonRoot, RAIL_SANDBOX_TYPE, restartPolicy Always for a native sidecar,
and shareProcessNamespace on the pod (tools/scan/gke/webhook/patch.py).
*/}}
{{- define "railmon-gke.sidecarSpec" -}}
containerName: {{ .Values.sidecar.containerName }}
configPath: {{ .Values.sidecar.configPath | quote }}
nativeSidecar: {{ .Values.sidecar.nativeSidecar }}
{{- if not (kindIs "invalid" .Values.sidecar.runAsUser) }}
runAsUser: {{ .Values.sidecar.runAsUser }}
{{- end }}
{{- if not (kindIs "invalid" .Values.sidecar.runAsGroup) }}
runAsGroup: {{ .Values.sidecar.runAsGroup }}
{{- end }}
container:
  image: {{ include "railmon-gke.image" . | quote }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args: ["scan", "--mode", "pod", "--register", "--no-feature-file"]
  workingDir: /tmp
  env:
    - name: POD_NAME
      valueFrom: {fieldRef: {fieldPath: metadata.name}}
    - name: POD_NAMESPACE
      valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
    - name: POD_UID
      valueFrom: {fieldRef: {fieldPath: metadata.uid}}
    - name: NODE_NAME
      valueFrom: {fieldRef: {fieldPath: spec.nodeName}}
    # Empty when the pod has no owner label, which the scan treats as unset.
    - name: RAIL_OWNER
      valueFrom: {fieldRef: {fieldPath: "metadata.labels['rail.datrail.io/owner']"}}
    - name: RAIL_POD_INFO_DIR
      value: /etc/podinfo
    - name: RAIL_HOST_ID
      value: {{ .Values.clusterName | quote }}
    - name: RAIL_CENTER_URL
      value: {{ include "railmon-gke.gkeScanUrl" . | quote }}
    - name: RAIL_CENTER_CA_FILE
      value: /etc/rail/ca/ca.crt
    - name: RAIL_AUTH_MODE
      value: bearer
    - name: RAIL_AUTH_TOKEN_FILE
      value: /var/run/rail/token
    - name: RAIL_SCAN_INTERVAL_IN_SECONDS
      value: {{ .Values.sidecar.intervalSeconds | quote }}
    - name: RAIL_EVIDENCE_BUNDLE_OUTPUT
      value: /tmp/evidence-bundle.json
    - name: RAIL_REGISTRATION_OUTPUT
      value: /tmp/registration.json
    - name: RAIL_HEALTH_FILE
      value: /tmp/railmon-health.json
    - name: HOME
      value: /tmp
    {{- if .Values.sidecar.collectSystemPrompt }}
    - name: RAIL_COLLECT_SYSTEM_PROMPT
      value: "1"
    {{- end }}
    {{- with .Values.sidecar.extraEnv }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
    seccompProfile:
      type: RuntimeDefault
  resources:
    {{- toYaml .Values.sidecar.resources | nindent 4 }}
  livenessProbe:
    exec:
      command: ["railmon", "scan", "--health-check"]
    periodSeconds: 60
    timeoutSeconds: 10
    failureThreshold: 1
  volumeMounts:
    - name: rail-scan-podinfo
      mountPath: /etc/podinfo
      readOnly: true
    - name: rail-scan-token
      mountPath: /var/run/rail
      readOnly: true
    - name: rail-scan-ca
      mountPath: /etc/rail/ca
      readOnly: true
    - name: rail-scan-tmp
      mountPath: /tmp
volumes:
  - name: rail-scan-podinfo
    downwardAPI:
      items:
        - path: labels
          fieldRef: {fieldPath: metadata.labels}
  # Mounted in the sidecar only. Its audience is gke-scan's, so neither Rail
  # Center nor the Kubernetes API accepts it; the kubelet rotates it.
  - name: rail-scan-token
    projected:
      sources:
        - serviceAccountToken:
            audience: {{ .Values.gkeScan.audience | quote }}
            expirationSeconds: 3600
            path: token
  - name: rail-scan-ca
    configMap:
      name: rail-scan-ca
  - name: rail-scan-tmp
    emptyDir:
      sizeLimit: {{ .Values.sidecar.tmpSizeLimit }}
{{- end -}}

{{/* Egress to DNS: the kube-dns pods, and NodeLocal DNSCache. Called with the root context. */}}
{{- define "railmon-gke.dnsEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ .Values.networkPolicy.dns.kubeDnsNamespace }}
      podSelector:
        matchLabels:
          {{- toYaml .Values.networkPolicy.dns.kubeDnsPodLabels | nindent 10 }}
  ports:
    - {protocol: UDP, port: 53}
    - {protocol: TCP, port: 53}
{{- with .Values.networkPolicy.dns.nodeLocalCidrs }}
# NodeLocal DNSCache: allowing only the kube-dns pods blocks DNS where it runs.
- to:
    {{- range . }}
    - ipBlock:
        cidr: {{ . }}
    {{- end }}
  ports:
    - {protocol: UDP, port: 53}
    - {protocol: TCP, port: 53}
{{- end }}
{{- end -}}
