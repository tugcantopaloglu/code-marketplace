param(
    [string]$Path,
    [switch]$ValidateOnly,
    [switch]$BootstrapAccess
)

$ErrorActionPreference = 'Stop'
$taskNamespace = 'code-marketplace'
$taskIdentity = "system:serviceaccount:${taskNamespace}:code-marketplace-deployer"
$taskKubectlArguments = @('--namespace', $taskNamespace)
if (!$BootstrapAccess) { $taskKubectlArguments += @('--as', $taskIdentity) }

function Assert-ManifestScope($taskObject) {
    if (!$taskObject) { throw 'Empty Kubernetes document' }
    if ($taskObject.kind -eq 'List' -and $taskObject.apiVersion -eq 'v1') {
        if (!$taskObject.items) { throw 'Empty Kubernetes list' }
        foreach ($taskItem in $taskObject.items) { Assert-ManifestScope $taskItem }
        return
    }
    if ($taskObject.metadata.namespace -ne $taskNamespace) { throw 'Every resource must explicitly use namespace code-marketplace' }
    if (!$taskObject.metadata.name -or $taskObject.metadata.generateName) { throw 'An explicit resource name is required' }
    $taskType = "$($taskObject.apiVersion)/$($taskObject.kind)"
    if ($BootstrapAccess) {
        $taskBootstrapTypes = @{
            'v1/ServiceAccount' = 'code-marketplace-deployer'
            'rbac.authorization.k8s.io/v1/Role' = 'code-marketplace-deployer'
            'rbac.authorization.k8s.io/v1/RoleBinding' = 'code-marketplace-deployer'
        }
        if (!$taskBootstrapTypes.ContainsKey($taskType) -or $taskObject.metadata.name -ne $taskBootstrapTypes[$taskType]) { throw 'Bootstrap only accepts the dedicated namespaced deployer account and role' }
        if ($taskObject.kind -eq 'ServiceAccount' -and $taskObject.automountServiceAccountToken -ne $false) { throw 'Deployer token mounting must be disabled' }
        if ($taskObject.kind -eq 'Role') {
            $taskRoleGroups = @{'configmaps'=''; 'secrets'=''; 'services'=''; 'deployments'='apps'; 'jobs'='batch'; 'cronjobs'='batch'; 'ingresses'='networking.k8s.io'; 'networkpolicies'='networking.k8s.io'; 'pods'=''; 'pods/log'=''; 'persistentvolumeclaims'=''}
            foreach ($taskRule in $taskObject.rules) {
                if ($taskRule.nonResourceURLs -or $taskRule.apiGroups -contains '*' -or $taskRule.resources -contains '*' -or $taskRule.verbs -contains '*') { throw 'Wildcard and non-resource permissions are forbidden' }
                foreach ($taskResource in $taskRule.resources) {
                    if (!$taskRoleGroups.ContainsKey($taskResource) -or @($taskRule.apiGroups).Count -ne 1 -or $taskRule.apiGroups[0] -ne $taskRoleGroups[$taskResource]) { throw 'Deployer role contains an unexpected resource or API group' }
                    $taskAllowedVerbs = @('get','list','watch','create','patch','update')
                    if ($taskResource -in @('pods','pods/log','persistentvolumeclaims')) { $taskAllowedVerbs = @('get','list','watch') }
                    if (@($taskRule.verbs | Where-Object { $_ -notin $taskAllowedVerbs }).Count) { throw 'Deployer role contains an unexpected permission' }
                }
            }
        }
        if ($taskObject.kind -eq 'RoleBinding') {
            if ($taskObject.roleRef.apiGroup -ne 'rbac.authorization.k8s.io' -or $taskObject.roleRef.kind -ne 'Role' -or $taskObject.roleRef.name -ne 'code-marketplace-deployer') { throw 'Cluster role references are forbidden' }
            if (@($taskObject.subjects).Count -ne 1 -or $taskObject.subjects[0].kind -ne 'ServiceAccount' -or $taskObject.subjects[0].name -ne 'code-marketplace-deployer' -or $taskObject.subjects[0].namespace -ne $taskNamespace) { throw 'Only the local deployer service account can receive this role' }
        }
        return
    }
    if ($taskType -notin @('v1/ConfigMap','v1/Secret','v1/Service','apps/v1/Deployment','batch/v1/Job','batch/v1/CronJob','networking.k8s.io/v1/Ingress','networking.k8s.io/v1/NetworkPolicy')) { throw 'Cluster-scoped, storage, RBAC and unsupported resource types are forbidden' }
    if ($taskObject.kind -eq 'Service') {
        if (($taskObject.spec.type -and $taskObject.spec.type -ne 'ClusterIP') -or $taskObject.spec.externalIPs -or $taskObject.spec.loadBalancerIP -or $taskObject.spec.loadBalancerClass) { throw 'Only internal ClusterIP services are permitted' }
    }
    $taskPod = $null
    if ($taskObject.kind -in @('Deployment','Job')) { $taskPod = $taskObject.spec.template.spec }
    if ($taskObject.kind -eq 'CronJob') { $taskPod = $taskObject.spec.jobTemplate.spec.template.spec }
    if ($taskPod) {
        if ($taskPod.hostNetwork -or $taskPod.hostPID -or $taskPod.hostIPC -or $taskPod.nodeName -or $taskPod.priorityClassName) { throw 'Host access and global placement overrides are forbidden' }
        if ($taskPod.automountServiceAccountToken -ne $false) { throw 'Workload service account tokens must be disabled' }
        foreach ($taskVolume in $taskPod.volumes) {
            if ($taskVolume.persistentVolumeClaim) {
                if ($taskVolume.persistentVolumeClaim.claimName -ne 'extensions') { throw 'Only the existing extensions PVC can be mounted' }
            } elseif (!$taskVolume.configMap -and !$taskVolume.secret) { throw 'Only the existing PVC, ConfigMaps and Secrets are permitted as volumes' }
        }
        foreach ($taskContainer in (@($taskPod.containers) + @($taskPod.initContainers) + @($taskPod.ephemeralContainers))) {
            if (!$taskContainer) { continue }
            if (@($taskContainer.ports | Where-Object { $_.hostPort }).Count) { throw 'Host ports are forbidden' }
            if ($taskContainer.securityContext.privileged -or $taskContainer.securityContext.allowPrivilegeEscalation -ne $false -or $taskContainer.securityContext.readOnlyRootFilesystem -ne $true -or $taskContainer.securityContext.capabilities.add) { throw 'Containers must retain restricted security settings' }
            if (@($taskContainer.securityContext.capabilities.drop) -notcontains 'ALL') { throw 'All capabilities must be dropped' }
        }
    }
}

function Add-ManifestDocument($taskObject) {
    if ($taskObject.kind -eq 'List' -and $taskObject.apiVersion -eq 'v1') {
        foreach ($taskItem in $taskObject.items) { Add-ManifestDocument $taskItem }
    } else { $taskDocuments.Add($taskObject) }
}

if ($Path) {
    $taskResolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $taskJson = & kubectl @taskKubectlArguments apply --dry-run=client --validate=false --output=json --filename $taskResolvedPath
    if ($LASTEXITCODE -ne 0) { throw 'Client dry-run failed; no resources were applied' }
    $taskJson = $taskJson -join "`n"
} else {
    if (![Console]::IsInputRedirected) { throw 'Supply -Path or pipe Kubernetes JSON through stdin' }
    $taskJson = [Console]::In.ReadToEnd()
}
try {
    $taskReader = [Newtonsoft.Json.JsonTextReader]::new([IO.StringReader]::new($taskJson))
    $taskReader.SupportMultipleContent = $true
    $taskDocuments = [System.Collections.Generic.List[object]]::new()
    while ($taskReader.Read()) {
        $taskToken = [Newtonsoft.Json.Linq.JToken]::ReadFrom($taskReader)
        $taskDocument = $taskToken.ToString([Newtonsoft.Json.Formatting]::None) | ConvertFrom-Json -Depth 100
        Assert-ManifestScope $taskDocument
        Add-ManifestDocument $taskDocument
    }
    $taskReader.Close()
    if (!$taskDocuments.Count) { throw 'No Kubernetes resources supplied' }
} catch { throw "Manifest validation failed: $($_.Exception.Message)" }
$taskSnapshot = @{apiVersion='v1'; kind='List'; items=@($taskDocuments.ToArray())} | ConvertTo-Json -Depth 100 -Compress
if ($ValidateOnly) { Write-Output 'Namespace and resource scope validated'; exit 0 }
if (!$BootstrapAccess) {
    $taskPVCJson = & kubectl @taskKubectlArguments get persistentvolumeclaim extensions --output=json
    if ($LASTEXITCODE -ne 0) { throw 'Existing PVC check failed; no resources were applied' }
    $taskPVC = ($taskPVCJson -join "`n") | ConvertFrom-Json -Depth 100
    if ($taskPVC.metadata.namespace -ne $taskNamespace -or $taskPVC.spec.volumeName -ne 'code-marketplace-data' -or $taskPVC.status.phase -ne 'Bound') { throw 'The namespace PVC must remain bound to code-marketplace-data' }
}
$taskSnapshot | & kubectl @taskKubectlArguments apply --filename -
if ($LASTEXITCODE -ne 0) { throw 'Namespaced apply failed; inspect the reported resource status before retrying' }
