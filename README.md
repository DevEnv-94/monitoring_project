# monitoring_project

The purpose of this project was to gain experience with the Prometheus monitoring system and its ecosystem. The entire project was automated using **Ansible**, with the exception of the graphs in Grafana.

The following technologies were used in the project: Linux, Prometheus, Ansible, Grafana, Alertmanager, Nginx (web server), Docker, Certbot (Let's Encrypt), Pushgateway exporter, cadvisor exporter (Docker exporter), Mysqld exporter, Wordpress (in Docker Compose with Mysqld), Node exporter, and Nginx exporter.

## Requrimenets

* Define variables on [hosts](https://github.com/DevEnv-94/monitoring_project/blob/master/hosts) file:

```ini
[node]
# IP address of your machine

[node:vars]
ansible_user= # User on your instance
ansible_become=true # Like a sudo command, must be true
ansible_become_pass= # Password for the user
domain= # Your domain name. You can get one from a site like namecheap.com, or use a free service like sslip.io or nip.io (do not include the "www" subdomain)

[prometheus]
# IP address of your machine

[prometheus:vars]
ansible_user= # User on your instance
ansible_become=true # Like a sudo command, must be true
ansible_become_pass= # Password for the user
domain= # Your domain name. You can get one from a site like namecheap.com, or use a free service like sslip.io or nip.io (do not include the "www" subdomain)
backup_user= # In this case, it is just the ansible user for the [node] instance. For testing purposes.
deadmanssnitch_url= # See https://deadmanssnitch.com/docs for more information
pageduty_service_key= # See https://www.pagerduty.com/docs/guides/prometheus-integration-guide/ for more information
slack_api_url= # See https://grafana.com/blog/2020/02/25/step-by-step-guide-to-setting-up-prometheus-alertmanager-with-slack-pagerduty-and-gmail/ for more information
slack_channel= # Must be the same name as the Slack channel, without the "#" symbol

#NB1: The domain names in the [node] and [prometheus] sections must be different, but you can use the domain from the [node] section with an additional subdomain for the [prometheus] section, for example grafana.yourdomain.com
#NB2: If you have chosen sslip.io or nip.io as your domain, #NB1 does not apply, but you may encounter a limit error from Let's Encrypt, because these domains acquire many certificates.
```


## Prometheus

* The Prometheus configuration file can be found [here](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/templates/prometheus.yml.j2).

* Metrics are collected every 15 seconds and rules are evaluated every 15 seconds.
```yaml
global:
  scrape_interval:     15s
  evaluation_interval: 15s
```

* All rules are in the "alerts" directory and are in YAML format.
```yaml
rule_files:
  - "alerts/*.yml"
```

* Alerting
```yaml
alerting:
  alertmanagers:
    - static_configs:
      - targets: ['{{ansible_eth1.ipv4.address}}:9093']
```

* Exporters on the [prometheus] instance connect to Prometheus using static_configs.
```yaml
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
    - targets: ['{{ansible_eth1.ipv4.address}}:9090']

  - job_name: 'prom_node_ex'
    static_configs:
      - targets: ['{{ansible_eth1.ipv4.address}}:9100']

  - job_name: 'prom_cadvisor_ex'
    static_configs:
      - targets: ['{{ansible_eth1.ipv4.address}}:8080']

  - job_name: 'pushgateway'
    honor_labels: true
    static_configs:
      - targets: ['{{ansible_eth1.ipv4.address}}:9091']

  - job_name: 'prom_nginx_ex'
    static_configs:
      - targets: ['{{ansible_eth1.ipv4.address}}:4040']
```

* Exporters on the [node] instance connect to Prometheus using file_sd_configs (discovery target). You can find more information about this [here](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#file_sd_config). The file of targets is in JSON format and can be found [here](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/templates/nodes.json.j2).
```yaml
  - job_name: 'nodes'
    file_sd_configs:
    - files:
      - '/etc/prometheus/prom-targets/*.json'
      refresh_interval: 10s
```


## Rules

* Some rules were taken from [here](https://awesome-prometheus-alerts.grep.to/rules.html) and modified for this project:

* Rules for [nginx](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/files/nginx.yml).

* Rules for [docker](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/files/cadvisor.yml).

* Rules for [mysql](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/files/mysql.yml).

* Rules for [node_exporter](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/files/nodes.yml).

* Rules for [prometheus](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/files/prometheus.yml)

* Rule for backing up data from Prometheus [here](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/files/prometheus_backup.yml)


## Alertmanager and alerts.

<details><summary>Alertmanager.yml config (click here)</summary>
<p>

```yaml
route:
  group_by: ['alertname']
  group_wait: 60s
  group_interval: 5m
  repeat_interval: 1h
  receiver: 'slack-warning' # The basic receiver gets alerts if they do not match any of the matchers.
  routes:
  - receiver: 'pagerduty-notifications'
    matchers:
    - severity="critical" 

  - receiver: 'slack-warning'
    matchers:
    - severity=~"warning|info" #Slack receives alerts with warning and info severity.

  - receiver: 'DeadMansSwitch'
    repeat_interval: 1m
    group_wait: 0s
    matchers:
    - severity="none"


receivers: 
- name: 'DeadMansSwitch'
  webhook_configs:
  - url: {{ deadmanssnitch_url }} #how to [https://deadmanssnitch.com/docs]
    send_resolved: false

- name: 'pagerduty-notifications' 
  pagerduty_configs:
  - service_key: {{ pageduty_service_key }} #How to https://www.pagerduty.com/docs/guides/prometheus-integration-guide/
    send_resolved: true

- name: 'slack-warning'
  slack_configs:
    - api_url: {{ slack_api_url }} #How to [https://grafana.com/blog/2020/02/25/step-by-step-guide-to-setting-up-prometheus-alertmanager-with-slack-pagerduty-and-gmail/]
      channel: '#{{ slack_channel }}'  # must be same name as slack channel name
      send_resolved: true
      icon_url: https://avatars3.githubusercontent.com/u/3380462
      title: {% raw %}|-
          [{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .CommonLabels.alertname }} for {{ .CommonLabels.job }}
          {{- if gt (len .CommonLabels) (len .GroupLabels) -}}
            {{" "}}(
            {{- with .CommonLabels.Remove .GroupLabels.Names }}
              {{- range $index, $label := .SortedPairs -}}
                {{ if $index }}, {{ end }}
                {{- $label.Name }}="{{ $label.Value -}}"
              {{- end }}
            {{- end -}}
            )
          {{- end }}
      text: >-
          {{ range .Alerts -}}
          *Alert:* {{ .Annotations.title }}{{ if .Labels.severity }} - `{{ .Labels.severity }}`{{ end }}
          *Description:* {{ .Annotations.description }}
          *Details:*
            {{ range .Labels.SortedPairs }} • *{{ .Name }}:* `{{ .Value }}`
            {{ end }}
          {{ end }} {% endraw %}


inhibit_rules:
  - source_matchers:
    - severity="critical"
    target_matchers:
    - severity="warning"
    equal: ['instance']
```

</p>
</details>

* Example of PagerDuty alert. How to connect PagerDuty and alertmanager you can find [here](https://www.pagerduty.com/docs/guides/prometheus-integration-guide/).

<details><summary>PagerDuty alert (click here)</summary>
<p>

![PagerDuty alert](https://github.com/DevEnv-94/monitoring_project/blob/master/images/pagerduty.png)

</p>
</details>

* Example of Slack alert. How to connect Slack and alertmanager you can find [here](https://grafana.com/blog/2020/02/25/step-by-step-guide-to-setting-up-prometheus-alertmanager-with-slack-pagerduty-and-gmail/).

<details><summary>Slack_channel alert (click here)</summary>
<p>

![Slack alert](https://github.com/DevEnv-94/monitoring_project/blob/master/images/slack_alert.png)

</p>
</details>

### DeadManSnitch alert. 
This receiver is created for the entire Prometheus monitoring system and always fires, sending a signal every minute. If Prometheus is down or there is a problem with Alertmanager, the signal will stop and you will receive an alert.


```yaml
  - alert: DeadMansSwitch
    annotations:
      description: This is a DeadMansSwitch meant to ensure that the entire Alerting pipeline is functional.
      summary: Alerting DeadMansSwitch
    expr: vector(1)
    labels:
     severity: none
```

This rule is intended to always be active.

![DeadManSnitch rule](https://github.com/DevEnv-94/monitoring_project/blob/master/images/deadmansnitch.png)

<details><summary>Dasboard on DeadManSnitch service (click here)</summary>
<p>

![DeaManSnitch dasboard](https://github.com/DevEnv-94/monitoring_project/blob/master/images/deadmansnitch_.png)

</p>
</details>

<details><summary>DeadManSnitch alert (click here)</summary>
<p>

![DeaManSnitch alert](https://github.com/DevEnv-94/monitoring_project/blob/master/images/deadmansnitch_alert.png)

</p>
</details>

## Grafana

* Node_exporter Full Dasboard. ID 1860

<details><summary>Node_exporter Dasboard (click here)</summary>
<p>

![Node_exporter dasboard](https://github.com/DevEnv-94/monitoring_project/blob/master/images/node_dasboard.png)

</p>
</details>

* Mysql Dasboard. ID 7362

<details><summary>Mysql Dasboard (click here)</summary>
<p>

![Mysql dasboard](https://github.com/DevEnv-94/monitoring_project/blob/master/images/mysql_dasboard.png)

</p>
</details>

* Dokcer Dasboard. ID 11600

<details><summary>Docker Dasboard (click here)</summary>
<p>

![Docker dasboard](https://github.com/DevEnv-94/monitoring_project/blob/master/images/docker_dasboard.png)

</p>
</details>

* Nginx dasboard was barely modified and based on 6482 dasboard. ID 15947

<details><summary>Nginx Dasboard (click here)</summary>
<p>

![Ngixn dasboard](https://github.com/DevEnv-94/monitoring_project/blob/master/images/nginx_dasboard.png)

</p>
</details>

## Nginx(WebServer)

In this project, Nginx serves as both a TLS termination proxy and a web server. It forwards traffic to Grafana on the [prometheus] instance and to Wordpress on the [node] instance.

### [node] instance

<details><summary>site config (click here)</summary>
<p>

```bash
log_format nginx_exporter '$remote_addr - $remote_user [$time_local] "$request" '
                          '$status $body_bytes_sent "$http_referer" '
                          '"$http_user_agent" "$http_x_forwarded_for" '
                          '$upstream_response_time $request_time';

server {
	listen 80 ;

	root /var/www/html;

	index index.html index.htm index.nginx-debian.html;

	server_name {{domain}} www.{{domain}};

  access_log /var/log/nginx/nginx.access.log nginx_exporter;

	location / {
	  return 301 https://$host$request_uri;
	}

}

upstream wordpress {
  server {{ansible_eth1.ipv4.address}}:8000;
}

server {
    listen 443 ssl http2 default_server;

    access_log /var/log/nginx/nginx.access.log nginx_exporter;

    index index.html index.php index.htm index.nginx-debian.html;

    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /path/to/dhparam
    ssl_dhparam /etc/nginx/dhparam;


    # intermediate configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (ngx_http_headers_module is required) (63072000 seconds)
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # verify chain of trust of OCSP response using Root CA and Intermediate certs
    ssl_trusted_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;

    # replace with the IP address of your resolver
    resolver 8.8.8.8;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }


    location / {
        proxy_pass http://wordpress;
        proxy_buffering on;
        proxy_buffers 12 12k;
        proxy_redirect off;
        
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
    }



}
```
</p>
</details>

<details><summary>Wordpress site (click here)</summary>
<p>

![Wordpress site](https://github.com/DevEnv-94/monitoring_project/blob/master/images/wordpress.png)

</p>
</details>

### [prometheus] instance

<details><summary>config site (click here)</summary>
<p>

```bash
log_format nginx_exporter '$remote_addr - $remote_user [$time_local] "$request" '
                         '$status $body_bytes_sent "$http_referer" '
                         '"$http_user_agent" "$http_x_forwarded_for" '
                        '$upstream_response_time $request_time';


map $http_upgrade $connection_upgrade {
   default upgrade;
   '' close;
  }

server {
	listen 80 ;

	root /var/www/html;

	index index.html index.htm index.nginx-debian.html;

	server_name {{domain}} www.{{domain}};

  access_log /var/log/nginx/nginx.access.log nginx_exporter;

	location / {
	  return 301 https://$host$request_uri;
	}

}


upstream grafana {
  server {{ansible_eth1.ipv4.address}}:3000;
}

server {
    listen 443 ssl http2 default_server;

    access_log /var/log/nginx/nginx.access.log nginx_exporter;

    index index.html index.php index.htm index.nginx-debian.html;

    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /path/to/dhparam
    ssl_dhparam /etc/nginx/dhparam;


    # intermediate configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (ngx_http_headers_module is required) (63072000 seconds)
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # verify chain of trust of OCSP response using Root CA and Intermediate certs
    ssl_trusted_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;

    # replace with the IP address of your resolver
    resolver 8.8.8.8;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }



    location / {
      proxy_set_header Host $http_host;
      proxy_pass http://grafana;
    }
    
    location /api/live {
      rewrite  ^/(.*)  /$1 break;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_set_header Host $http_host;
      proxy_pass http://grafana;
  }
    location /api/ruler/1/api/v1/rules {
      return 200;
    }

}
```

</p>
</details>

<details><summary>Grafana site (click here)</summary>
<p>

![Grafana site](https://github.com/DevEnv-94/monitoring_project/blob/master/images/grafana.png)

</p>
</details>


## Backup script and Pushgateway

There is a Prometheus backup script that creates snapshots, archives and compresses them, and then sends the data to the [node] instance. It also sends a prometheus_backup metric to pushgateway with a value of 1 if the script ran correctly and a value of 0 if it encountered an error. The script then deletes the created snapshots.

```bash
#!/bin/bash

# Set the URL for the snapshot endpoint
snapshot_url="http://${ansible_eth1.ipv4.address}:9090/api/v1/admin/tsdb/snapshot"

# Set the directory where snapshots are stored
snapshot_dir="/var/lib/docker/volumes/prometheus_data/_data/snapshots"

# Create a new directory for the backup
backup_dir=$(mktemp -d)

# Take the snapshot
if curl -X POST "$snapshot_url" && 
    cd "$snapshot_dir" &&
    tar -czf "$backup_dir/prometheus_backup_data-$(date '+%Y-%m-%d').tar.gz" * &&
    rsync -e "ssh -o StrictHostKeyChecking=no" -zc --remove-source-files "$backup_dir/prometheus_backup_data-"* "user@${hostvars[groups['node'][0]]['ansible_eth1']['ipv4']['address']}:/tmp/" &&
    rm -r "$snapshot_dir"/*
then
    # Report success
    echo 'prometheus_backup {type="boolean"} 1' | curl --data-binary @- "http://${ansible_eth1.ipv4.address}:9091/metrics/job/prometheus_backup_data/instance/prometheus"
else
    # Report failure
    echo 'prometheus_backup {type="boolean"} 0' | curl --data-binary @- "http://${ansible_eth1.ipv4.address}:9091/metrics/job/prometheus_backup_data/instance/prometheus"
fi

# Clean up temporary files
rm -r "$backup_dir"
```

<details><summary>Prometheus_backup metric (click here)</summary>
<p>

![Prometheus_backup metric](https://github.com/DevEnv-94/monitoring_project/blob/master/images/prom_backup_metric.png)

</p>
</details>

* To create a Prometheus data snapshot, start Prometheus with the following command. 

```bash
--web.enable-admin-api
```

* Scripts are executed by a cron job every day at 17:00.

```yaml
- name: Ensure a prometheus backup script runs every day at 17:00.
  ansible.builtin.cron:
    name: "backup prometheus data"
    user: root
    minute: "0"
    hour: "17"
    job: "/opt/prom_backup/prometheus_backup_script.sh"
    cron_file: prometheus_data_backup
  tags: backup_prometheus
```

## Security

All exporters, Alertmanager, and Prometheus interact with each other on a local network. There is no access to them from the internet.

## License

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
