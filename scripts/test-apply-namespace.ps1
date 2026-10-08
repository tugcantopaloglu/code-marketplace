$ErrorActionPreference = 'Stop'
$global:taskScopeCalls = [System.Collections.Generic.List[object]]::new()
$global:taskScopePVC = @{apiVersion='v1'; kind='PersistentVolumeClaim'; metadata=@{name='extensions'; namespace='code-marketplace'}; spec=@{volumeName='code-marketplace-data'}; status=@{phase='Bound'}}
function kubectl {
    $taskArguments = @($args)
    $global:taskScopeCalls.Add($taskArguments)
    $global:LASTEXITCODE = 0
    if ($taskArguments -contains '--dry-run=client') {
        if ($global:taskScopeFixture -is [array]) { return ($global:taskScopeFixture | ForEach-Object { $_ | ConvertTo-Json -Depth 100 }) -join "`n" }
        return $global:taskScopeFixture | ConvertTo-Json -Depth 100
    }
    if ($taskArguments -contains 'get') { return $global:taskScopePVC | ConvertTo-Json -Depth 100 }
    if ($taskArguments -contains 'apply') {
        $global:taskScopeApplied = ($input | ForEach-Object { $_ }) -join "`n"
        return 'configured'
    }
    throw 'Unexpected mock kubectl call'
}
function Assert-ScopeRejected($taskFixture,[switch]$Bootstrap) {
    $global:taskScopeFixture = $taskFixture
    $global:taskScopeCalls.Clear()
    $taskRejected = $false
    try { & ./scripts/apply-namespace.ps1 -Path ./README.md -BootstrapAccess:$Bootstrap } catch { $taskRejected = $true }
    if (!$taskRejected) { throw 'An invalid manifest was accepted' }
    foreach ($taskCall in $global:taskScopeCalls) {
        if ($taskCall -contains 'apply' -and $taskCall -notcontains '--dry-run=client') { throw 'A write occurred before scope rejection' }
    }
}
$taskValid = @{apiVersion='v1'; kind='ConfigMap'; metadata=@{name='marketplace-test'; namespace='code-marketplace'}; data=@{value='test'}}
$global:taskScopeFixture = $taskValid
& ./scripts/apply-namespace.ps1 -Path ./README.md
if ($global:taskScopeCalls.Count -ne 3) { throw 'Expected client dry-run, PVC lookup, and one validated apply' }
foreach ($taskCall in $global:taskScopeCalls) {
    if ($taskCall[0] -ne '--namespace' -or $taskCall[1] -ne 'code-marketplace' -or $taskCall[2] -ne '--as' -or $taskCall[3] -ne 'system:serviceaccount:code-marketplace:code-marketplace-deployer') { throw 'Namespace or limited-account restriction was lost' }
}
if (($global:taskScopeApplied | ConvertFrom-Json).items[0].metadata.name -ne 'marketplace-test') { throw 'Apply did not use the validated JSON snapshot' }
$global:taskScopeFixture = @($taskValid,$taskValid)
& ./scripts/apply-namespace.ps1 -Path ./README.md
if (@(($global:taskScopeApplied | ConvertFrom-Json).items).Count -ne 2) { throw 'Multiple JSON documents were not preserved' }
$global:taskScopeFixture = @{apiVersion='v1'; kind='List'; items=@($taskValid,$taskValid)}
& ./scripts/apply-namespace.ps1 -Path ./README.md
if (@(($global:taskScopeApplied | ConvertFrom-Json).items).Count -ne 2 -or ($global:taskScopeApplied | ConvertFrom-Json).items[0].kind -ne 'ConfigMap') { throw 'Kubernetes lists were not flattened before apply' }
$global:taskScopeCalls.Clear()
& ./scripts/apply-namespace.ps1 -Path ./README.md -ValidateOnly
if ($global:taskScopeCalls.Count -ne 1) { throw 'Validate-only mode attempted a cluster write or PVC lookup' }
foreach ($taskKind in @('PersistentVolume','StorageClass','Namespace','ClusterRole','ClusterRoleBinding','PersistentVolumeClaim')) {
    Assert-ScopeRejected @{apiVersion='v1'; kind=$taskKind; metadata=@{name='unexpected'; namespace='code-marketplace'}}
}
Assert-ScopeRejected @{apiVersion='v1'; kind='ConfigMap'; metadata=@{name='foreign'; namespace='default'}}
Assert-ScopeRejected @{apiVersion='v1'; kind='ConfigMap'; metadata=@{name='missing-namespace'}}
Assert-ScopeRejected @{apiVersion='v1'; kind='List'; items=@($taskValid,@{apiVersion='v1'; kind='ConfigMap'; metadata=@{name='foreign'; namespace='kube-system'}})}
Assert-ScopeRejected @($taskValid,@{apiVersion='v1'; kind='ConfigMap'; metadata=@{name='foreign'; namespace='kube-system'}})
Assert-ScopeRejected @{apiVersion='v1'; kind='Service'; metadata=@{name='nodeport'; namespace='code-marketplace'}; spec=@{type='NodePort'}}
foreach ($taskVolume in @(@{name='host'; hostPath=@{path='/'}},@{name='foreign'; persistentVolumeClaim=@{claimName='another-application'}})) {
    Assert-ScopeRejected @{apiVersion='batch/v1'; kind='Job'; metadata=@{name='unsafe'; namespace='code-marketplace'}; spec=@{template=@{spec=@{automountServiceAccountToken=$false; volumes=@($taskVolume)}}}}
}
Assert-ScopeRejected @{apiVersion='rbac.authorization.k8s.io/v1'; kind='RoleBinding'; metadata=@{name='code-marketplace-deployer'; namespace='code-marketplace'}; roleRef=@{kind='ClusterRole'; name='cluster-admin'}; subjects=@(@{kind='ServiceAccount'; name='code-marketplace-deployer'; namespace='code-marketplace'})} -Bootstrap
$taskSafeJob = @{apiVersion='batch/v1'; kind='Job'; metadata=@{name='safe'; namespace='code-marketplace'}; spec=@{template=@{spec=@{automountServiceAccountToken=$false; containers=@(@{name='test'; image='example:test'; securityContext=@{allowPrivilegeEscalation=$false; readOnlyRootFilesystem=$true; capabilities=@{drop=@('ALL')}}})}}}}
foreach ($taskUnsafeField in @('hostNetwork','hostPID','hostIPC','nodeName','priorityClassName')) {
    $taskUnsafeJob = ($taskSafeJob | ConvertTo-Json -Depth 100) | ConvertFrom-Json -AsHashtable
    $taskUnsafeJob.spec.template.spec[$taskUnsafeField] = 'unsafe'
    Assert-ScopeRejected $taskUnsafeJob
}
$taskUnsafeJob = ($taskSafeJob | ConvertTo-Json -Depth 100) | ConvertFrom-Json -AsHashtable
$taskUnsafeJob.spec.template.spec.containers[0].ports = @(@{hostPort=3001; containerPort=3001})
Assert-ScopeRejected $taskUnsafeJob
foreach ($taskUnsafeField in @('privileged','allowPrivilegeEscalation')) {
    $taskUnsafeJob = ($taskSafeJob | ConvertTo-Json -Depth 100) | ConvertFrom-Json -AsHashtable
    $taskUnsafeJob.spec.template.spec.containers[0].securityContext[$taskUnsafeField] = $true
    Assert-ScopeRejected $taskUnsafeJob
}
$global:taskScopeFixture = $taskSafeJob
& ./scripts/apply-namespace.ps1 -Path ./README.md
$taskUnsafeJob = ($taskSafeJob | ConvertTo-Json -Depth 100) | ConvertFrom-Json -AsHashtable
$taskUnsafeJob.spec.template.spec.preemptionPolicy = 'Never'
Assert-ScopeRejected $taskUnsafeJob
$taskBootstrapRole = @{apiVersion='rbac.authorization.k8s.io/v1'; kind='Role'; metadata=@{name='code-marketplace-deployer'; namespace='code-marketplace'}; rules=@(@{apiGroups=@(''); resources=@('configmaps'); verbs=@('get','create','patch')})}
$global:taskScopeFixture = @(@{apiVersion='v1'; kind='ServiceAccount'; metadata=@{name='code-marketplace-deployer'; namespace='code-marketplace'}; automountServiceAccountToken=$false},$taskBootstrapRole,@{apiVersion='rbac.authorization.k8s.io/v1'; kind='RoleBinding'; metadata=@{name='code-marketplace-deployer'; namespace='code-marketplace'}; roleRef=@{apiGroup='rbac.authorization.k8s.io'; kind='Role'; name='code-marketplace-deployer'}; subjects=@(@{kind='ServiceAccount'; name='code-marketplace-deployer'; namespace='code-marketplace'})})
$global:taskScopeCalls.Clear()
& ./scripts/apply-namespace.ps1 -Path ./README.md -BootstrapAccess
if ($global:taskScopeCalls.Count -ne 2 -or @($global:taskScopeCalls | Where-Object { $_ -contains '--as' }).Count) { throw 'Bootstrap did not remain in its distinct namespaced phase' }
foreach ($taskUnsafeRule in @(@{apiGroups=@('*'); resources=@('configmaps'); verbs=@('get')},@{apiGroups=@(''); resources=@('persistentvolumeclaims'); verbs=@('patch')},@{apiGroups=@(''); resources=@('secrets'); verbs=@('delete')},@{apiGroups=@('other.example'); resources=@('deployments'); verbs=@('get')})) {
    $taskUnsafeRole = ($taskBootstrapRole | ConvertTo-Json -Depth 100) | ConvertFrom-Json -AsHashtable
    $taskUnsafeRole.rules = @($taskUnsafeRule)
    Assert-ScopeRejected $taskUnsafeRole -Bootstrap
}
$global:taskScopeFixture = $taskValid
$global:taskScopeCalls.Clear()
$global:taskScopePVC.spec.volumeName = 'another-volume'
$taskRejected = $false
try { & ./scripts/apply-namespace.ps1 -Path ./README.md } catch { $taskRejected = $true }
if (!$taskRejected -or $global:taskScopeCalls.Count -ne 2) { throw 'Unexpected PVC binding was not rejected before apply' }
Write-Output 'Namespaced deployment guard passed; foreign resources and host access were rejected before writes.'
