-- A starting policy: devices of owners and admins may reach the platform
-- (the gateway's tunnel address) on the gateway API and dashboard ports and
-- by ping. Everything else stays denied until a policy allows it.
INSERT INTO vpn.policies (id, name, priority, action, groups, destinations, protocol, ports, description, created_by, created_at)
VALUES
    ('01900000-0000-7000-8000-0000000c0001', 'admins-to-platform', 100, 'allow', '{owner,admin}', '{platform}', 'tcp',
     '{3000,8000}', 'Dashboard and API on the gateway''s tunnel address', 'migration', now()),
    ('01900000-0000-7000-8000-0000000c0002', 'ping-platform', 110, 'allow', '{owner,admin,operator,analyst}', '{platform}', 'icmp',
     '{}', 'Reachability checks to the gateway', 'migration', now());
