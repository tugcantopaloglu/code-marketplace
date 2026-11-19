exec python3 - "$@" <<'PY'
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid

NAMESPACE = "code-marketplace"
IMAGE = "harbor.tai.com.tr/code-marketplace/code-marketplace:v5"
EXTENSION = "tusas.tusascode"
FILENAME = "internal-plusaicode-0.1.23.vsix"
ORIGINAL_FILENAME = FILENAME[len("internal-"):]
KEY_ID = "tusas-auto-v5"
POLICY = "marketplace-internal-policy"
SECRET = "marketplace-internal-auto-sign-v5"


def kubectl(*args, data=None):
    result = subprocess.run(
        ["kubectl", "-n", NAMESPACE, *args],
        input=json.dumps(data) if data is not None else None,
        capture_output=True, text=True, check=True,
    )
    return result.stdout


def resource(kind, name, optional=False):
    args = ("--ignore-not-found",) if optional else ()
    output = kubectl("get", kind, name, *args, "-o", "json")
    return json.loads(output) if output.strip() else None


def flags(args):
    values = {}
    for i, arg in enumerate(args):
        if arg.startswith("--"):
            flag, sep, value = arg.partition("=")
            values[flag] = value if sep else (
                args[i + 1] if i + 1 < len(args) and not args[i + 1].startswith("--") else None
            )
    return values


def uploader(uid, mode):
    number = int(uid)
    if number <= 0 or number == 65534 or number > 4294967294:
        raise ValueError(f"NFS dosya sahibi UID {number}. Dosyayı mevcut normal Linux hesabınızla kopyalayın.")
    if int(mode, 8) & 0o022:
        raise ValueError("Örnek VSIX grup veya diğer kullanıcılar için yazılabilir. Dosya sahibi chmod go-w DOSYA çalıştırmalı.")
    return str(number)


def local_file_owner(path, expected, size):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or size is not None and info.st_size != size:
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as package:
        opened = os.fstat(package.fileno())
        if not os.path.samestat(info, opened) or info.st_uid != opened.st_uid or info.st_mode != opened.st_mode:
            raise ValueError("Örnek VSIX okunurken değişti. Kopyalama tamamlandıktan sonra yeniden çalıştırın.")
        if expected:
            digest = hashlib.sha256()
            for block in iter(lambda: package.read(1 << 20), b""):
                digest.update(block)
            if digest.hexdigest() != expected:
                return None
        return opened.st_uid, format(stat.S_IMODE(opened.st_mode), "o")


def find_local_owner(directory, expected, size):
    preferred = directory / FILENAME
    try:
        owner = local_file_owner(preferred, expected, size)
        if owner is not None:
            return uploader(*owner)
        files = sorted(directory.iterdir())
        matches = []
        if expected:
            for path in files:
                if path != preferred and path.name.startswith("internal-") and path.suffix.lower() == ".vsix":
                    owner = local_file_owner(path, expected, size)
                    if owner is not None:
                        matches.append((path, owner))
        if len(matches) > 1:
            raise ValueError(f"Aynı VSIX birden fazla internal- adıyla bulundu. Kullanılacak dosyayı {FILENAME} olarak adlandırın.")
        if matches:
            path, owner = matches[0]
            print(f"Örnek VSIX bu adla bulundu: {path.name}", flush=True)
            return uploader(*owner)
        if (directory / ORIGINAL_FILENAME) in files:
            raise ValueError(f"{directory / ORIGINAL_FILENAME} mevcut. Dosya adını {FILENAME} yapıp betiği yeniden çalıştırın.")
        if preferred in files:
            print(f"{preferred} bu makinede görünüyor ancak boyut, SHA-256 veya dosya türü eşleşmedi.", flush=True)
        else:
            print(f"{directory} bu makinede görünüyor, ancak eşleşen internal-*.vsix dosyası bulunamadı.", flush=True)
    except (FileNotFoundError, NotADirectoryError):
        print(f"{directory} bu makinede görünmüyor.", flush=True)
    except PermissionError:
        print(f"{directory} bu terminalde okunamıyor.", flush=True)
    return None


def find_uploader(directory, expected, size, pod, container, incoming):
    local = find_local_owner(directory, expected, size)
    if local is not None:
        return local
    print("CronJob'un incoming mount'u salt okunur bir kontrol Job'u ile doğrulanıyor.", flush=True)
    mount = next(m for m in container["volumeMounts"] if m["mountPath"] == incoming)
    volume = next(v for v in pod["volumes"] if v["name"] == mount["name"])
    probe = """preferred=$1
expected=$2
size=$3
original=$4
directory=$(dirname "$preferred")
matches_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    before=$(stat -c '%d %i %u %a %s' "$1") || return 1
    if [ -n "$size" ] && [ "$(stat -c '%s' "$1")" != "$size" ]; then return 1; fi
    if [ -n "$expected" ]; then
        actual=$(sha256sum < "$1") || return 1
        [ "${actual%% *}" = "$expected" ] || return 1
    fi
    [ "$(stat -c '%d %i %u %a %s' "$1")" = "$before" ]
}
if [ ! -d "$directory" ]; then
    printf '%s\\n' "CronJob incoming dizini görünmüyor: $directory" >&2
    exit 1
fi
selected=""
if matches_file "$preferred"; then
    selected=$preferred
elif [ -n "$expected" ]; then
    for file in "$directory"/internal-*; do
        [ "$file" != "$preferred" ] || continue
        case "$file" in *.[Vv][Ss][Ii][Xx]) ;; *) continue ;; esac
        if matches_file "$file"; then
            if [ -n "$selected" ]; then
                printf '%s\\n' "Aynı VSIX birden fazla internal- adıyla bulundu. Kullanılacak dosyayı $(basename "$preferred") olarak adlandırın." >&2
                exit 1
            fi
            selected=$file
        fi
    done
fi
if [ -z "$selected" ]; then
    if [ -f "$directory/$original" ]; then
        printf '%s\\n' "$original mevcut. Dosya adını $(basename "$preferred") yapıp betiği yeniden çalıştırın." >&2
    elif [ -e "$preferred" ] || [ -L "$preferred" ]; then
        printf '%s\\n' "$preferred mevcut ancak boyut, SHA-256 veya dosya türü eşleşmedi." >&2
    else
        printf '%s\\n' "$directory görünüyor ancak eşleşen internal-*.vsix dosyası bulunamadı. Beklenen örnek: $(basename "$preferred")." >&2
    fi
    exit 1
fi
printf '%s\\n' "Örnek VSIX: $(basename "$selected")"
stat -c 'MARKETPLACE_OWNER %u %a' "$selected"
"""
    pod_keys = ("securityContext", "imagePullSecrets", "nodeSelector", "affinity",
                "tolerations", "serviceAccountName", "runtimeClassName", "schedulerName")
    probe_pod = {key: pod[key] for key in pod_keys if key in pod}
    probe_pod.update({
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "volumes": [volume],
        "containers": [{
            "name": "inspect-owner", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
            "command": ["/bin/sh"], "args": ["-ec", probe, "probe", str(PurePosixPath(incoming) / FILENAME),
                                         expected, str(size) if size is not None else "", ORIGINAL_FILENAME],
            "volumeMounts": [{**mount, "readOnly": True}],
            "securityContext": container.get("securityContext", {}),
            "resources": container.get("resources", {}),
        }],
    })
    name = "marketplace-owner-" + uuid.uuid4().hex[:10]
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name, "namespace": NAMESPACE},
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "ttlSecondsAfterFinished": 300,
                    "template": {"spec": probe_pod}}}
    kubectl("create", "-f", "-", data=job)
    timeout = time.monotonic() + 100
    while time.monotonic() < timeout:
        status = resource("job", name).get("status", {})
        conditions = {c["type"] for c in status.get("conditions", []) if c["status"] == "True"}
        if conditions & {"Failed", "Complete"}:
            try:
                logs = kubectl("logs", "job/" + name)
            except subprocess.CalledProcessError as error:
                raise ValueError(f"Kontrol Job'u: {name}. Log okunamadı. {error.stderr.strip()}") from None
            match = re.search(r"^MARKETPLACE_OWNER ([0-9]+) ([0-7]+)$", logs, re.MULTILINE)
            if "Complete" in conditions and match:
                found = next((line for line in logs.splitlines() if line.startswith("Örnek VSIX: ")), None)
                if found:
                    print(found, flush=True)
                return uploader(*match.groups())
            raise ValueError(f"UID kontrolü başarısız. Kontrol Job'u: {name}. {logs.strip()}")
        time.sleep(2)
    raise ValueError(f"UID kontrolü zaman aşımına uğradı. Kontrol Job'u: {name}.")


def public_key(pem):
    public = subprocess.run(
        ["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem, capture_output=True, check=True
    ).stdout
    prefix = bytes.fromhex("302a300506032b6570032100")
    if not public.startswith(prefix) or len(public) != len(prefix) + 32:
        raise ValueError("OpenSSL beklenen Ed25519 açık anahtar biçimini döndürmedi.")
    return base64.b64encode(public[len(prefix):]).decode()


def release_policy():
    secret = resource("secret", SECRET, optional=True)
    if secret is None:
        with tempfile.TemporaryDirectory(prefix="marketplace-key-") as directory:
            key = Path(directory) / "internal-private.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True)
            pem = key.read_bytes()
            key_policy = {"keys": {KEY_ID: {"publicKey": public_key(pem),
                                           "extensions": [EXTENSION]}}}
            secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": SECRET, "namespace": NAMESPACE},
                      "type": "Opaque", "data": {
                          "internal-private.pem": base64.b64encode(pem).decode(),
                          "internal-policy.json": base64.b64encode(json.dumps(key_policy).encode()).decode(),
                      }}
            try:
                kubectl("create", "-f", "-", data=secret)
            except subprocess.CalledProcessError:
                raise ValueError(f"Kubernetes Secret oluşturulamadı: {NAMESPACE}/{SECRET}. Yetkileri kontrol edin.") from None
    entry = json.loads(base64.b64decode(secret["data"]["internal-policy.json"], validate=True))["keys"][KEY_ID]
    pem = base64.b64decode(secret["data"]["internal-private.pem"], validate=True)
    if entry["extensions"] != [EXTENSION] or entry["publicKey"] != public_key(pem):
        raise ValueError("Mevcut Secret'ın açık anahtarı veya eklenti kapsamı beklenen policy ile eşleşmiyor.")
    return entry


def configure_policy(entry):
    cm = resource("configmap", POLICY, optional=True)
    existing = cm.get("data", {}) if cm else {}
    policy = json.loads(existing.get("internal-policy.json", '{"keys":{}}'))
    keys = policy["keys"]
    if KEY_ID in keys and keys[KEY_ID] != entry:
        raise ValueError("ConfigMap'te aynı keyId için farklı bir anahtar var.")
    if keys.get(KEY_ID) == entry:
        return
    keys[KEY_ID] = entry
    merged = json.dumps(policy, ensure_ascii=False, indent=2)
    if cm is None:
        kubectl("create", "-f", "-", data={"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": POLICY, "namespace": NAMESPACE}, "data": {"internal-policy.json": merged}})
        return
    target = {"op": "add", "path": "/data/internal-policy.json", "value": merged} if "data" in cm else {
        "op": "add", "path": "/data", "value": {"internal-policy.json": merged}}
    patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": cm["metadata"]["resourceVersion"]}, target]
    kubectl("patch", "configmap", POLICY, "--type=json", "-p", json.dumps(patch))


def configure_cronjob(name, job, pod, index, importer, incoming, uid):
    replace = {
        "--internal-policy": "/internal-policy/policy.json",
        "--internal-auto-sign-key": "/internal-auto-sign/internal-private.pem",
        "--internal-auto-sign-key-id": KEY_ID,
        "--internal-uploader-uid": uid,
    }
    removed = {"/internal-policy", "/internal-auto-sign", "/sandbox-trust"}
    managed = {"internal-policy", "internal-auto-sign"}
    other = [c for i, c in enumerate(pod["containers"]) if i != index] + pod.get("initContainers", [])
    other_names = {m["name"] for container in other for m in container.get("volumeMounts", [])}
    if managed & other_names:
        raise ValueError("Mevcut policy veya Secret volume adı başka bir konteyner tarafından kullanılıyor.")
    old_mounts = importer["volumeMounts"]
    removed_names = {m["name"] for m in old_mounts if m["mountPath"] in removed}
    mounts = [dict(m) for m in old_mounts if m["mountPath"] not in removed]
    next(m for m in mounts if m["mountPath"] == incoming)["readOnly"] = False
    mounts.extend({"name": name, "mountPath": "/" + name, "readOnly": True} for name in sorted(managed))
    references = {m["name"] for m in mounts} | other_names
    volumes = [v for v in pod["volumes"] if v["name"] not in managed
               and (v["name"] not in removed_names or v["name"] in references)]
    volumes.extend([
        {"name": "internal-policy", "configMap": {"name": POLICY, "items": [
            {"key": "internal-policy.json", "path": "policy.json"}]}},
        {"name": "internal-auto-sign", "secret": {"secretName": SECRET, "defaultMode": 288, "items": [
            {"key": "internal-private.pem", "path": "internal-private.pem"}]}},
    ])
    args = iter(importer["args"])
    updated = []
    for arg in args:
        flag, sep, _ = arg.partition("=")
        if flag in replace or flag in {"--sandbox-trust", "--sandbox-max-age"}:
            if not sep:
                value = next(args, "")
                if not value or value.startswith("--"):
                    raise ValueError(f"Eksik importer argüman değeri: {flag}")
        elif flag != "--internal-auto-skip-sandbox":
            updated.append(arg)
    for flag, value in replace.items():
        updated.extend((flag, value))
    updated.append("--internal-auto-skip-sandbox")
    path = "/spec/jobTemplate/spec/template/spec"
    container_path = f"{path}/containers/{index}"
    fields = {"image": IMAGE, "args": updated, "volumeMounts": mounts}
    patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": job["metadata"]["resourceVersion"]}]
    patch.extend({"op": "add", "path": f"{container_path}/{key}", "value": value} for key, value in fields.items())
    patch.append({"op": "add", "path": f"{path}/volumes", "value": volumes})
    if all(importer.get(key) == value for key, value in fields.items()) and pod["volumes"] == volumes:
        return
    kubectl("patch", "cronjob", name, "--type=json", "-p", json.dumps(patch))


def main():
    parser = argparse.ArgumentParser(description="Sandbox kapalı ortamda v5 kurum içi VSIX importer kurulumunu yapar.")
    parser.add_argument("--cronjob", default="extension-importer", help="code-marketplace namespace içindeki importer CronJob adı")
    parser.add_argument("--incoming", type=Path, default=Path("/mailarchive/code-marketplace/incoming"),
                        help="Bu makinede görünen NFS incoming dizini")
    options = parser.parse_args()
    if os.name != "posix":
        raise ValueError("Betiği Linux kubectl makinesinde çalıştırın.")
    os.umask(0o077)
    job = resource("cronjob", options.cronjob)
    pod = job["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    index, importer = next((i, c) for i, c in enumerate(pod["containers"]) if c["name"] == "importer")
    args = importer["args"]
    values = flags(args)
    if args[0] != "import" or values.get("--sandbox-mode") != "disabled":
        raise ValueError("Mevcut CronJob import komutunu ve --sandbox-mode disabled ayarını kullanmalı.")
    if not pod.get("securityContext", {}).get("fsGroup"):
        raise ValueError("CronJob pod securityContext.fsGroup ayarı gerekli.")
    incoming = values.get("--incoming-dir")
    if not incoming or not PurePosixPath(incoming).is_absolute() or not any(
        m["mountPath"] == incoming for m in importer.get("volumeMounts", [])
    ):
        raise ValueError("Importer incoming mount'u bulunamadı.")
    recorded = values.get("--internal-uploader-uid")
    if recorded and values.get("--internal-auto-sign-key-id") == KEY_ID and (
        "--internal-auto-skip-sandbox" in values and values["--internal-auto-skip-sandbox"] in {None, "true", "True", "TRUE", "1", "t", "T"}
    ):
        uid = uploader(recorded, "644")
    else:
        expected = os.environ.get("MARKETPLACE_SETUP_SHA256", "")
        size = os.environ.get("MARKETPLACE_SETUP_SIZE", "")
        uid = find_uploader(options.incoming, expected, int(size) if size else None, pod, importer, incoming)
    print(f"Seçilen dosya sahibi UID: {uid}", flush=True)
    entry = release_policy()
    configure_policy(entry)
    configure_cronjob(options.cronjob, job, pod, index, importer, incoming, uid)
    print(f"Hazır. {NAMESPACE}/{options.cronjob} sonraki çalışmasında incoming klasörünü işler.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr.strip(), file=sys.stderr)
        raise SystemExit("Kurulum komutu başarısız oldu. Yukarıdaki çıktıyı kontrol edin.")
    except FileNotFoundError as error:
        raise SystemExit(f"Gerekli komut bulunamadı: {error.filename}")
    except (KeyError, StopIteration, ValueError, OSError) as error:
        raise SystemExit(f"Kurulum durdu: {error}")
PY
