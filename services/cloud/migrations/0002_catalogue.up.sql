-- Seed catalogue: flavors, pinned images and version-1 templates.
--
-- Images are pinned by content, so provisioning is reproducible: VM images
-- by SHA-256 (verified by the node agent before first use), container
-- images by registry digest. The checksums below were computed from the
-- official downloads and compared with the publishers' checksum files:
--   CirrOS 0.6.2   MD5 c8fc807773e5354afe61636071771906 matches download.cirros-cloud.net/0.6.2/MD5SUMS
--   Ubuntu 24.04   SHA256SUMS of cloud-images.ubuntu.com/releases/noble/release-20261017/

INSERT INTO cloud.flavors (id, name, vcpus, memory_mib, disk_gib) VALUES
    ('01900000-0000-7000-8000-00000000f001', 'pf.nano',   1,  256,  1),
    ('01900000-0000-7000-8000-00000000f002', 'pf.micro',  1,  512,  2),
    ('01900000-0000-7000-8000-00000000f003', 'pf.small',  1, 1024, 10),
    ('01900000-0000-7000-8000-00000000f004', 'pf.medium', 2, 2048, 20);

INSERT INTO cloud.images (id, name, kind, source, sha256, os) VALUES
    ('01900000-0000-7000-8000-00000000a001', 'cirros-0.6.2', 'vm',
     'https://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img',
     '07e44a73e54c94d988028515403c1ed762055e01b83a767edf3c2b387f78ce00', 'CirrOS 0.6.2'),
    ('01900000-0000-7000-8000-00000000a002', 'ubuntu-24.04-20261017', 'vm',
     'https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img',
     '04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94', 'Ubuntu 24.04 LTS'),
    ('01900000-0000-7000-8000-00000000a003', 'alpine-3.22', 'container',
     'docker.io/library/alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f',
     NULL, 'Alpine Linux 3.22'),
    ('01900000-0000-7000-8000-00000000a004', 'nginx-1.28-alpine', 'container',
     'docker.io/library/nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236',
     NULL, 'nginx 1.28 on Alpine');

INSERT INTO cloud.templates
    (id, name, version, kind, description, image_id, default_flavor_id, cloud_config, static_network, command, cap_add)
VALUES
    ('01900000-0000-7000-8000-00000000b001', 'cirros', 1, 'vm',
     'CirrOS test VM: 20 MB image, boots in seconds in 256 MiB. Gets its address by DHCP.',
     '01900000-0000-7000-8000-00000000a001', '01900000-0000-7000-8000-00000000f001',
     '{}', false, '[]', '[]'),
    ('01900000-0000-7000-8000-00000000b002', 'ubuntu-24.04', 1, 'vm',
     'Ubuntu Server 24.04 LTS cloud image with cloud-init. Configures a static address, so it also works on lab networks.',
     '01900000-0000-7000-8000-00000000a002', '01900000-0000-7000-8000-00000000f003',
     '{"package_update": false, "ssh_pwauth": false}', true, '[]', '[]'),
    ('01900000-0000-7000-8000-00000000b003', 'alpine-sleeper', 1, 'container',
     'Alpine container that idles. Useful for network tests from inside a workload.',
     '01900000-0000-7000-8000-00000000a003', '01900000-0000-7000-8000-00000000f001',
     '{}', false, '["sleep", "infinity"]', '[]'),
    ('01900000-0000-7000-8000-00000000b004', 'nginx', 1, 'container',
     'nginx web server on port 80.',
     '01900000-0000-7000-8000-00000000a004', '01900000-0000-7000-8000-00000000f001',
     '{}', false, '[]', '["CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE"]');
