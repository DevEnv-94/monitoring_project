# monitoring_project

This project was made for gaining some experience with Prometheus monitoring system and it's ecosystem.
Ansible was used in project for gaining experience as well and like a guideline through the project.

Technologies is used in the project: Prometheus, Ansible, Grafana, Alertmanager, Nginx(Webserver), Docker, Certbot(Let'sencrypt), Pushgateway_exporter, cadvisor_exporter(Docker_exporter), Mysqld_exporter, Wordpress(in Docker-Compose witf Mysqld), Node_exporter, Nginx_exporter.


## Roles decription

* [alertmanager](https://github.com/DevEnv-94/monitoring_project/blob/master/alertmanager/tasks/main.yml) role: creates requirement directory puts here alertmanager.yml config and starts alertmanager in docker on eth1 ip4 address on 9093 port.

* [docker_compose](https://github.com/DevEnv-94/monitoring_project/blob/master/docker_compose/tasks/main.yml) role: installs all requirement packages and then installs docker and docker-compose.

* [Wordpress](https://github.com/DevEnv-94/monitoring_project/tree/master/wordpress/tasks) role: creates directory puts here [docker-compose.yml](https://github.com/DevEnv-94/monitoring_project/blob/master/wordpress/templates/docker-compose.yml.j2) and starts wordpress in docker.


## Requrimenets

* Installed [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) on your machine

* Install community.general and community.docker collections
```bash
   $ ansible-galaxy collection install community.general
   $ ansible-galaxy collection install community.docker
```
* Two instances and Ubuntu 20.04 on it.

* LAN network between instances on eth1 interface on instances.

* Sudo priveleges on your user on instances

* Define variables on [hosts](https://github.com/DevEnv-94/monitoring_project/blob/master/hosts) file:

```ini
[node]
# IP address of your machine


[node:vars]
ansible_user= # User on your instance
ansible_become=true # Like a sudo behind a command, should be true
ansible_become_pass= # Password of your user
domain= # Your domain name, for example you can get it here https://www.namecheap.com or use something free like https://sslip.io or https://nip.io . (without www subdomain)

[prometheus]
# IP address of your machine


[prometheus:vars]
ansible_user= # User on your instance
ansible_become=true # Like a sudo behind a command, should be true
ansible_become_pass= # Password of your user
domain=  # Your domain name, for example you can get it here https://www.namecheap.com or use something free like https://sslip.io or https://nip.io . (without www subdomain)
backup_user= # In this case without any adjustment of project you should use same user which you used on [node] section.

#NB: Domain names on node and prometheus sections have to be different but you can use on [prometheus] section your [node] domain with additional subdomain for example [grafana.yourdomain.com]
```

