# Setting up ulimits using MachineConfig on OpenShift

## Validation

Before and after applying the change we will need to verify the value of `memlock` defined on `ulimit`.

There are two places where we can/should validate, crio runtime and using `ulimit` tool.

Log into your compute node (worker label):

```
oc debug node/ip-10-0-178-126.us-east-2.compute.internal
```

Don't forget to run `chroot /host` right after.

Then you can execute `crio-status config` to see if there is any setting in place under `[crio.runtime]` more specifically the `default_ulimits` attribute. If that is a new cluster and/or no customization was made it should look like this:

``` 
sh-4.4# crio-status config
[crio]
  root = "/var/lib/containers/storage"
  runroot = "/run/containers/storage"
  storage_driver = "overlay"
  storage_option = ["overlay.override_kernel_check=1"]
  log_dir = "/var/log/crio/pods"
  version_file = "/var/run/crio/version"
  version_file_persist = "/var/lib/crio/version"
  clean_shutdown_file = "/var/lib/crio/clean.shutdown"
  internal_wipe = true
  [crio.api]
    grpc_max_send_msg_size = 16777216
    grpc_max_recv_msg_size = 16777216
    listen = "/var/run/crio/crio.sock"
    stream_address = ""
    stream_port = "10010"
    stream_enable_tls = false
    stream_tls_cert = ""
    stream_tls_key = ""
    stream_tls_ca = ""
    stream_idle_timeout = ""
  [crio.runtime]
    seccomp_use_default_when_empty = false
    no_pivot = false
    selinux = true
    log_to_journald = false
    drop_infra_ctr = true
    read_only = false
    conmon_env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    hooks_dir = ["/etc/containers/oci/hooks.d", "/run/containers/oci/hooks.d"]
    default_capabilities = ["CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "SETGID", "SETUID", "SETPCAP", "NET_BIND_SERVICE", "KILL"]
    default_env = ["NSS_SDB_USE_CACHE=no"]
    default_sysctls = ["net.ipv4.ping_group_range=0 2147483647"]
    device_ownership_from_security_context = false
    default_runtime = "runc"
    decryption_keys_path = "/etc/crio/keys/"
    conmon = "/usr/bin/conmon"
    conmon_cgroup = "pod"
    seccomp_profile = ""
    apparmor_profile = "crio-default"
    blockio_config_file = ""
    irqbalance_config_file = "/etc/sysconfig/irqbalance"
    rdt_config_file = ""
    cgroup_manager = "systemd"
    default_mounts_file = ""
    container_exits_dir = "/var/run/crio/exits"
    container_attach_socket_dir = "/var/run/crio"
    bind_mount_prefix = ""
    uid_mappings = ""
    gid_mappings = ""
    log_level = "info"
    log_filter = ""
    namespaces_dir = "/var/run"
    pinns_path = "/usr/bin/pinns"
    pids_limit = 1024
    log_size_max = -1
    ctr_stop_timeout = 30
    separate_pull_cgroup = ""
    infra_ctr_cpuset = ""
    absent_mount_sources_to_reject = ["/etc/hostname"]
    [crio.runtime.runtimes]
      [crio.runtime.runtimes.runc]
        runtime_config_path = ""
        runtime_path = "/usr/bin/runc"
        runtime_type = "oci"
        runtime_root = "/run/runc"
        allowed_annotations = ["io.containers.trace-syscall"]
        DisallowedAnnotations = ["cpu-quota.crio.io", "io.kubernetes.cri.rdt-class", "io.kubernetes.cri-o.ShmSize", "io.kubernetes.cri-o.Devices", "cpu-load-balancing.crio.io", "io.kubernetes.cri-o.userns-mode", "io.kubernetes.cri-o.UnifiedCgroup", "irq-load-balancing.crio.io"]
  [crio.image]
    default_transport = "docker://"
    global_auth_file = "/var/lib/kubelet/config.json"
    pause_image = "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:ba0643d21fdd3d65ff8a031daa9c3e12c957d2ecdce1859dfd37faa9a67a8968"
    pause_image_auth_file = "/var/lib/kubelet/config.json"
    pause_command = "/usr/bin/pod"
    signature_policy = ""
    image_volumes = "mkdir"
    big_files_temporary_dir = ""
  [crio.network]
    cni_default_network = ""
    network_dir = "/etc/kubernetes/cni/net.d/"
    plugin_dirs = ["/var/lib/cni/bin", "/usr/libexec/cni"]
  [crio.metrics]
    enable_metrics = true
    metrics_collectors = ["operations", "operations_latency_microseconds_total", "operations_latency_microseconds", "operations_errors", "image_pulls_layer_size", "containers_oom_total", "containers_oom"]
    metrics_port = 9537
    metrics_socket = ""
    metrics_cert = ""
    metrics_key = "" 
```

Another way to validate is to check with `ulimit -a`:

```
sh-4.4# ulimit -a
core file size          (blocks, -c) unlimited
data seg size           (kbytes, -d) unlimited
scheduling priority             (-e) 0
file size               (blocks, -f) unlimited
pending signals                 (-i) 252726
max locked memory       (kbytes, -l) 64
max memory size         (kbytes, -m) unlimited
open files                      (-n) 1048576
pipe size            (512 bytes, -p) 8
POSIX message queues     (bytes, -q) 819200
real-time priority              (-r) 0
stack size              (kbytes, -s) 8192
cpu time               (seconds, -t) unlimited
max user processes              (-u) 4194304
virtual memory          (kbytes, -v) unlimited
file locks                      (-x) unlimited
```

## Setting `memlock` attribute

In order to define the content for the `ulimit` we need to encode to base64 the config and set it as data in a `MachineConfig` manifest.

```
cat << EOF | base64 -w0
[crio.runtime]
default_ulimits = [
"memlock=-1:-1"
]
EOF

W2NyaW8ucnVudGltZV0KZGVmYXVsdF91bGltaXRzID0gWwoibWVtbG9jaz0tMTotMSIKXQo=
``` 

This will be setting the `memlock` as unlimited.

Copy that data hash and add it in the `MachineConfig` right after `base64,` like this:

```
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  annotations:
  labels:
    machineconfiguration.openshift.io/role: worker
  name: 02-worker-container-runtime
spec:
  config:
    ignition:
      version: 3.2.0
    storage:
      files:
      - contents:
          source: data:text/plain;charset=utf-8;base64,W2NyaW8ucnVudGltZV0KZGVmYXVsdF91bGltaXRzID0gWwoibWVtbG9jaz0tMTotMSIKXQo=
        mode: 420
        overwrite: true
        path: /etc/crio/crio.conf.d/10-custom
```

Save the `MachineConfig` as `mc.yaml` and run:

```
$ oc apply -f mc.yaml
machineconfig.machineconfiguration.openshift.io/02-worker-container-runtime configured
```

## Monitor update progress

After creating the machine config it will render (merging all configs) a new configuration that will start rolling out the config to all compute nodes with the label `machineconfiguration.openshift.io/role: worker`

In order to monitor that progress we can check the status of the `MachineConfigPool` with `oc get mcp -w`:

```
oc get mcp -w
NAME     CONFIG                                             UPDATED   UPDATING   DEGRADED   MACHINECOUNT   READYMACHINECOUNT   UPDATEDMACHINECOUNT   DEGRADEDMACHINECOUNT   AGE
master   rendered-master-ef1843714e6c03578dc99e372aae751a   True      False      False      3              3                   3                     0                      3h4m
worker   rendered-worker-35511118128848355a7712563f84d006   True      False      False      3              3                   3                     0                      3h4m
worker   rendered-worker-35511118128848355a7712563f84d006   False     True       False      3              0                   0                     0                      3h4m
worker   rendered-worker-35511118128848355a7712563f84d006   False     True       False      3              0                   0                     0                      3h4m
worker   rendered-worker-35511118128848355a7712563f84d006   False     True       False      3              1                   1                     0                      3h6m
worker   rendered-worker-35511118128848355a7712563f84d006   False     True       False      3              1                   1                     0                      3h6m
worker   rendered-worker-35511118128848355a7712563f84d006   False     True       False      3              2                   2                     0                      3h8m
worker   rendered-worker-35511118128848355a7712563f84d006   False     True       False      3              2                   2                     0                      3h8m
worker   rendered-worker-98a0de75f37f8308c4598b46ca446daa   True      False      False      3              3                   3                     0                      3h10
```

Now we can execute the validation procedure again to check if the value is defined properly:

```
sh-4.4# crio-status config | grep default_ulimits
default_ulimits = ["memlock=-1:-1"]
```

```
sh-4.4# ulimit -a
core file size          (blocks, -c) unlimited
data seg size           (kbytes, -d) unlimited
scheduling priority             (-e) 0
file size               (blocks, -f) unlimited
pending signals                 (-i) 252726
max locked memory       (kbytes, -l) unlimited
max memory size         (kbytes, -m) unlimited
open files                      (-n) 1048576
pipe size            (512 bytes, -p) 8
POSIX message queues     (bytes, -q) 819200
real-time priority              (-r) 0
stack size              (kbytes, -s) 8192
cpu time               (seconds, -t) unlimited
max user processes              (-u) 4194304
virtual memory          (kbytes, -v) unlimited
file locks                      (-x) unlimited
``` 