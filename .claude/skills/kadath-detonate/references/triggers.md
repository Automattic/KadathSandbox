# Staging and triggering, by sample type

All paths are relative to the repo root `/Users/fioa8c/WORK/KadathSandbox`. The host URL is `http://127.0.0.1:8088`. Samples under `samples/` are bind-mounted read-only and symlinked into the webroot **on container start**, so after adding or removing a sample you must recreate the container:

```bash
docker compose up -d --force-recreate --wait wordpress
```

Confirm the link was made: `docker compose logs wordpress | grep 'linked samples' -A3 | tail`.

## Identify the type first

```bash
head -40 <sample>        # a "Plugin Name:" header => plugin; "Theme Name:"/style.css => theme
grep -nE '\$_(GET|POST|REQUEST|COOKIE|SERVER)\[' <sample> | head   # request params => webshell
grep -nE 'curl_|wp_remote_|fsockopen|file_get_contents\(.?http|include\s+.?http' <sample>  # network => dropper
```

A zip is unpacked and re-classified from its contents.

## Plugin

```bash
SLUG=<slug>
mkdir -p samples/plugins/$SLUG
cp <sample.php or unpacked dir/*> samples/plugins/$SLUG/
docker compose up -d --force-recreate --wait wordpress
```

Then activate and trigger. Pick the path by where the payload lives.

**Default: `init` / `admin_init` payload (almost every WordPress backdoor).** The persistence logic runs on hooks that fire on ordinary requests, not on the activation hook, so activate with the CLI (a state change — the sample is not loaded into that CLI process, so it does no harm) and trigger with page views. Verified: this captures the full account-creation / hiding payload in the page-view trace.

```bash
docker compose exec -T wordpress wp plugin activate $SLUG      # state change only
curl -s -o /dev/null http://127.0.0.1:8088/                    # front page -> fires init -> one trace
```
If the payload is admin-only, also drive an admin page while logged in (login recipe below), e.g. `curl -s -b $CJ -o /dev/null http://127.0.0.1:8088/wp-admin/`.

**Only if the payload is in `register_activation_hook`:** the activation itself must be traced, so activate over HTTP. Fetch the nonce **while the plugin is still inactive** — an active self-hiding plugin removes its own action links from the page, so you cannot scrape them after activation. Anchors are HTML-entity-encoded (`&#038;`), so decode before use.

```bash
CJ=$(mktemp)
curl -s -c $CJ -b $CJ -o /dev/null http://127.0.0.1:8088/wp-login.php
curl -s -c $CJ -b $CJ -o /dev/null \
  --data 'log=admin&pwd=sandbox&wp-submit=Log+In&testcookie=1' http://127.0.0.1:8088/wp-login.php
# scrape THIS plugin's own activate href while it is inactive, then decode entities
HREF=$(curl -s -b $CJ "http://127.0.0.1:8088/wp-admin/plugins.php" \
  | grep -o "href=\"plugins.php?action=activate[^\"]*${SLUG}[^\"]*\"" | head -1 \
  | sed 's/^href="//; s/"$//; s/&#038;/\&/g; s/&amp;/\&/g')
curl -s -b $CJ -o /dev/null "http://127.0.0.1:8088/wp-admin/${HREF}"   # traced activation
```

**To trigger anti-removal behaviour** (deactivate/delete blocks) on a self-hiding sample, do not scrape its links — they are gone once it is active. Build the URL yourself with a fresh nonce from any form on `plugins.php`:

```bash
PLUGIN="${SLUG}/${SLUG}.php"          # or the actual main-file path inside the plugin dir
NONCE=$(curl -s -b $CJ "http://127.0.0.1:8088/wp-admin/plugins.php" \
  | grep -oE '_wpnonce=[a-f0-9]+' | head -1 | cut -d= -f2)
curl -s -b $CJ -o /dev/null -w 'deactivate -> %{http_code}\n' \
  "http://127.0.0.1:8088/wp-admin/plugins.php?action=deactivate&plugin=${PLUGIN}&_wpnonce=${NONCE}"
# a 403 / wp_die here is the anti-removal block firing (and is itself traced)
```

## Theme

```bash
SLUG=<slug>
mkdir -p samples/themes/$SLUG
cp -R <unpacked theme>/* samples/themes/$SLUG/
docker compose up -d --force-recreate --wait wordpress
docker compose exec -T wordpress wp theme activate $SLUG
curl -s -o /dev/null http://127.0.0.1:8088/                    # front page renders the theme -> trace
```

## Webshell / loose PHP

```bash
cp <sample.php> samples/webroot/shell.php
docker compose up -d --force-recreate --wait wordpress
```

The shell does nothing until called with the input it expects. Discover it, do not guess:

```bash
grep -noE "\$_(GET|POST|REQUEST|COOKIE)\['[^']+'\]" samples/webroot/shell.php | sort -u
# look for a password gate, a command param, an eval sink
grep -nE 'password|pass|auth|md5|sha1|==|===' samples/webroot/shell.php | head
```

Then craft requests that reach the sink. Examples:

```bash
curl -s "http://127.0.0.1:8088/shell.php?<param>=<benign-probe>"          # GET
curl -s -d '<param>=<benign-probe>' "http://127.0.0.1:8088/shell.php"     # POST
curl -s -H 'Cookie: <name>=<value>' "http://127.0.0.1:8088/shell.php"     # cookie-gated
```

Keep probes benign (`id`, `echo`, a `phpinfo`) — you are confirming the sink executes and watching the trace and network artifacts, not running attacker commands. Each request writes its own trace; note which request produced which trace by timestamp.

## Dropper

Stage and trigger as a webshell or plugin, then watch the network side: the fetch of the next stage goes through the gateway and is decrypted. After triggering, `kadath-analyze` will find it in `artifacts/mitm/flows.mitm` and `artifacts/dns/dns.log`. If the drop URL is HTTPS the payload body is in the decrypted flow; if it is raw TCP to a non-web port the SYN is in `artifacts/dropped.log` and the connection is blocked.

## Zip / archive

```bash
mkdir -p /tmp/unpack && unzip -o <sample.zip> -d /tmp/unpack && ls -R /tmp/unpack | head -40
```

Re-classify from the contents. For a plugin or theme zip you have two options: drop-in the unpacked directory (fast, above), or upload the original zip through **wp-admin → Plugins → Add New → Upload** to observe installer-time behaviour as a victim would. Use the upload path when the sample may act during installation, not just activation.
