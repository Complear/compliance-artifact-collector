{{- define "cac.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cac.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "cac.labels" -}}
app.kubernetes.io/name: {{ include "cac.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "cac.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- define "cac.inputConfigMap" -}}
{{- .Values.input.existingConfigMap | default (printf "%s-input" (include "cac.fullname" .)) -}}
{{- end -}}

{{- define "cac.outputClaim" -}}
{{- .Values.output.persistence.existingClaim | default (printf "%s-output" (include "cac.fullname" .)) -}}
{{- end -}}

{{/* The pod spec shared by the Job and the CronJob. */}}
{{- define "cac.podSpec" -}}
{{- if and (not .Values.input.existingClaim) (not .Values.input.existingConfigMap) (not .Values.input.files) (not .Values.input.binaryFiles) -}}
{{- fail "set input.files, input.existingConfigMap or input.existingClaim" -}}
{{- end -}}
{{- if and .Values.signing.enabled (not .Values.signing.existingSecret) -}}
{{- fail "signing.enabled needs signing.existingSecret (with cosign.key)" -}}
{{- end -}}
{{- if and .Values.push.enabled (not .Values.envFromSecret) -}}
{{- fail "push.enabled needs envFromSecret (with COMPLEAR_URL and COMPLEAR_UPLOAD_KEY)" -}}
{{- end -}}
restartPolicy: Never
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
securityContext:
  {{- toYaml .Values.podSecurityContext | nindent 2 }}
containers:
  - name: collector
    image: {{ include "cac.image" . }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    command: ["sh", "-c"]
    args:
      - |
        set -e
        python -m cac collect "/work/in/{{ .Values.input.productFile }}" --out "/work/out/{{ .Values.output.file }}"{{ if .Values.signing.enabled }} --sign-key /keys/cosign.key{{ if .Values.signing.transparencyLog }} --transparency-log{{ end }}{{ end }}
        {{- if .Values.validate }}
        python -m cac validate "/work/out/{{ .Values.output.file }}"
        {{- end }}
        {{- if .Values.push.enabled }}
        python -m cac push "/work/out/{{ .Values.output.file }}"
        {{- end }}
        {{- if not .Values.output.persistence.enabled }}
        cat "/work/out/{{ .Values.output.file }}"
        {{- end }}
    env:
      - name: HOME
        value: /tmp
      {{- if .Values.signing.enabled }}
      - name: COSIGN_PASSWORD
        valueFrom:
          secretKeyRef:
            name: {{ .Values.signing.existingSecret }}
            key: COSIGN_PASSWORD
            optional: true
      {{- end }}
      {{- with .Values.env }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
    {{- if .Values.envFromSecret }}
    envFrom:
      - secretRef:
          name: {{ .Values.envFromSecret }}
    {{- end }}
    securityContext:
      {{- toYaml .Values.securityContext | nindent 6 }}
    resources:
      {{- toYaml .Values.resources | nindent 6 }}
    volumeMounts:
      - name: input
        mountPath: /work/in
        readOnly: true
        {{- if and .Values.input.existingClaim .Values.input.subPath }}
        subPath: {{ .Values.input.subPath }}
        {{- end }}
      - name: output
        mountPath: /work/out
      - name: tmp
        mountPath: /tmp
      {{- if .Values.signing.enabled }}
      - name: keys
        mountPath: /keys
        readOnly: true
      {{- end }}
volumes:
  - name: input
    {{- if .Values.input.existingClaim }}
    persistentVolumeClaim:
      claimName: {{ .Values.input.existingClaim }}
      readOnly: true
    {{- else }}
    configMap:
      name: {{ include "cac.inputConfigMap" . }}
    {{- end }}
  - name: output
    {{- if .Values.output.persistence.enabled }}
    persistentVolumeClaim:
      claimName: {{ include "cac.outputClaim" . }}
    {{- else }}
    emptyDir: {}
    {{- end }}
  - name: tmp
    emptyDir: {}
  {{- if .Values.signing.enabled }}
  - name: keys
    secret:
      secretName: {{ .Values.signing.existingSecret }}
      items:
        - key: cosign.key
          path: cosign.key
  {{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
