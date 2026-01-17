#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

// Function to print transport settings for Clash proxy
void print_transport(cJSON *streamSettings, FILE *fp, bool skip_cert) {
    if (!streamSettings) {
        fprintf(fp, "  network: tcp\n");
        fprintf(fp, "  tls: false\n");
        return;
    }
    cJSON *network = cJSON_GetObjectItem(streamSettings, "network");
    const char *net = network ? cJSON_GetStringValue(network) : "tcp";
    if (strcmp(net, "ws") == 0 || strcmp(net, "websocket") == 0) {
        fprintf(fp, "  network: ws\n");
        cJSON *wsSettings = cJSON_GetObjectItem(streamSettings, "wsSettings");
        if (wsSettings) {
            cJSON *path = cJSON_GetObjectItem(wsSettings, "path");
            if (path) fprintf(fp, "  ws-path: %s\n", cJSON_GetStringValue(path));
            cJSON *headers = cJSON_GetObjectItem(wsSettings, "headers");
            if (headers) {
                cJSON *host = cJSON_GetObjectItem(headers, "Host");
                if (host) fprintf(fp, "  ws-headers:\n    Host: %s\n", cJSON_GetStringValue(host));
            }
        }
    } else if (strcmp(net, "grpc") == 0) {
        fprintf(fp, "  network: grpc\n");
        cJSON *grpcSettings = cJSON_GetObjectItem(streamSettings, "grpcSettings");
        if (grpcSettings) {
            cJSON *serviceName = cJSON_GetObjectItem(grpcSettings, "serviceName");
            if (serviceName) fprintf(fp, "  grpc-service-name: %s\n", cJSON_GetStringValue(serviceName));
        }
    } else if (strcmp(net, "h2") == 0 || strcmp(net, "http") == 0) {
        fprintf(fp, "  network: h2\n");
        cJSON *httpSettings = cJSON_GetObjectItem(streamSettings, "httpSettings");
        if (httpSettings) {
            cJSON *path = cJSON_GetObjectItem(httpSettings, "path");
            if (path) fprintf(fp, "  h2-path: %s\n", cJSON_GetStringValue(path));
            cJSON *host = cJSON_GetObjectItem(httpSettings, "host");
            if (host && cJSON_IsArray(host)) {
                cJSON *h = cJSON_GetArrayItem(host, 0);
                if (h) fprintf(fp, "  h2-host:\n    - %s\n", cJSON_GetStringValue(h));
            }
        }
    } else if (strcmp(net, "kcp") == 0) {
        fprintf(fp, "  network: kcp\n");
    } else {
        fprintf(fp, "  network: %s\n", net);
    }
    // Handle TLS settings
    cJSON *security = cJSON_GetObjectItem(streamSettings, "security");
    if (security && (strcmp(cJSON_GetStringValue(security), "tls") == 0 || strcmp(cJSON_GetStringValue(security), "xtls") == 0)) {
        fprintf(fp, "  tls: true\n");
        if (skip_cert) fprintf(fp, "  skip-cert-verify: true\n");
        cJSON *tlsSettings = cJSON_GetObjectItem(streamSettings, "tlsSettings");
        if (!tlsSettings) tlsSettings = cJSON_GetObjectItem(streamSettings, "xtlsSettings");
        if (tlsSettings) {
            cJSON *serverName = cJSON_GetObjectItem(tlsSettings, "serverName");
            if (serverName) fprintf(fp, "  servername: %s\n", cJSON_GetStringValue(serverName));
            cJSON *alpn = cJSON_GetObjectItem(tlsSettings, "alpn");
            if (alpn && cJSON_IsArray(alpn)) {
                fprintf(fp, "  alpn:\n");
                int num = cJSON_GetArraySize(alpn);
                for (int j = 0; j < num; j++) {
                    cJSON *item = cJSON_GetArrayItem(alpn, j);
                    fprintf(fp, "    - \"%s\"\n", cJSON_GetStringValue(item));
                }
            }
        }
    } else {
        fprintf(fp, "  tls: false\n");
    }
}

// Main function: parses Xray config and generates Clash config
int main(int argc, char *argv[]) {
    // Parse command-line arguments
    char *server = "localhost";
    char *config_file = "config.json";
    char *output_file = "clash.yaml";
    if (argc > 1) {
        server = argv[1];
    }
    if (argc > 2) {
        config_file = argv[2];
    }
    if (argc > 3) {
        output_file = argv[3];
    }

    // Determine if to skip certificate verification
    bool skip_cert = false;
    if (strcmp(server, "localhost") == 0) {
        skip_cert = true;
    } else {
        bool is_ip = true;
        for (char *p = server; *p; p++) {
            if (!isdigit(*p) && *p != '.') {
                is_ip = false;
                break;
            }
        }
        if (is_ip || strlen(server) == 0) {
            skip_cert = true;
        }
    }

    FILE *out_fp = fopen(output_file, "w");
    if (!out_fp) {
        perror("Error opening output file");
        return 1;
    }

    // Read and parse the Xray config file
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        perror("Error opening file");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buffer = malloc(length + 1);
    if (!buffer) {
        fclose(fp);
        return 1;
    }
    fread(buffer, 1, length, fp);
    buffer[length] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(buffer);
    if (!root) {
        printf("Error parsing JSON\n");
        free(buffer);
        return 1;
    }

    // Output Clash config header
    fprintf(out_fp, "mixed-port: 7890\n");
    fprintf(out_fp, "socks-port: 7891\n");
    fprintf(out_fp, "redir-port: 7892\n");
    fprintf(out_fp, "allow-lan: true\n");
    fprintf(out_fp, "mode: rule\n");
    fprintf(out_fp, "log-level: info\n");
    fprintf(out_fp, "external-controller: 127.0.0.1:9090\n");
    fprintf(out_fp, "proxies:\n");

    char proxy_names[100][50];
    int proxy_count = 0;

    // Parse inbounds and generate proxies
    cJSON *inbounds = cJSON_GetObjectItem(root, "inbounds");
    if (inbounds && cJSON_IsArray(inbounds)) {
        int num_inbounds = cJSON_GetArraySize(inbounds);
        for (int i = 0; i < num_inbounds; i++) {
            cJSON *inbound = cJSON_GetArrayItem(inbounds, i);
            cJSON *protocol = cJSON_GetObjectItem(inbound, "protocol");
            cJSON *port = cJSON_GetObjectItem(inbound, "port");
            cJSON *settings = cJSON_GetObjectItem(inbound, "settings");
            cJSON *streamSettings = cJSON_GetObjectItem(inbound, "streamSettings");
            if (!protocol) continue;
            const char *proto = cJSON_GetStringValue(protocol);
            int p = port ? port->valueint : 0;

            // Handle different protocols
            if (strcmp(proto, "vmess") == 0) {
                cJSON *clients = cJSON_GetObjectItem(settings, "clients");
                if (!clients || !cJSON_IsArray(clients)) continue;
                cJSON *client = cJSON_GetArrayItem(clients, 0);
                if (!client) continue;
                cJSON *id = cJSON_GetObjectItem(client, "id");
                cJSON *alterId = cJSON_GetObjectItem(client, "alterId");
                fprintf(out_fp, "- name: \"vmess-%d\"\n", i);
                sprintf(proxy_names[proxy_count++], "vmess-%d", i);
                fprintf(out_fp, "  type: vmess\n");
                fprintf(out_fp, "  server: %s\n", server);
                fprintf(out_fp, "  port: %d\n", p);
                fprintf(out_fp, "  uuid: %s\n", id ? cJSON_GetStringValue(id) : "");
                fprintf(out_fp, "  alterId: %d\n", alterId ? alterId->valueint : 0);
                fprintf(out_fp, "  cipher: auto\n");
                print_transport(streamSettings, out_fp, skip_cert);
                if (skip_cert) fprintf(out_fp, "  skip-cert-verify: true\n");
            } else if (strcmp(proto, "vless") == 0) {
                cJSON *clients = cJSON_GetObjectItem(settings, "clients");
                if (!clients || !cJSON_IsArray(clients)) continue;
                cJSON *client = cJSON_GetArrayItem(clients, 0);
                if (!client) continue;
                cJSON *id = cJSON_GetObjectItem(client, "id");
                cJSON *flow = cJSON_GetObjectItem(client, "flow");
                fprintf(out_fp, "- name: \"vless-%d\"\n", i);
                sprintf(proxy_names[proxy_count++], "vless-%d", i);
                fprintf(out_fp, "  type: vless\n");
                fprintf(out_fp, "  server: %s\n", server);
                fprintf(out_fp, "  port: %d\n", p);
                fprintf(out_fp, "  uuid: %s\n", id ? cJSON_GetStringValue(id) : "");
                if (flow) fprintf(out_fp, "  flow: %s\n", cJSON_GetStringValue(flow));
                print_transport(streamSettings, out_fp, skip_cert);
                if (skip_cert) fprintf(out_fp, "  skip-cert-verify: true\n");
            } else if (strcmp(proto, "trojan") == 0) {
                cJSON *clients = cJSON_GetObjectItem(settings, "clients");
                if (!clients || !cJSON_IsArray(clients)) continue;
                cJSON *client = cJSON_GetArrayItem(clients, 0);
                if (!client) continue;
                cJSON *password = cJSON_GetObjectItem(client, "password");
                fprintf(out_fp, "- name: \"trojan-%d\"\n", i);
                sprintf(proxy_names[proxy_count++], "trojan-%d", i);
                fprintf(out_fp, "  type: trojan\n");
                fprintf(out_fp, "  server: %s\n", server);
                fprintf(out_fp, "  port: %d\n", p);
                fprintf(out_fp, "  password: %s\n", password ? cJSON_GetStringValue(password) : "");
                print_transport(streamSettings, out_fp, skip_cert);
                if (skip_cert) fprintf(out_fp, "  skip-cert-verify: true\n");
            } else if (strcmp(proto, "shadowsocks") == 0) {
                cJSON *clients = cJSON_GetObjectItem(settings, "clients");
                if (!clients || !cJSON_IsArray(clients)) continue;
                cJSON *client = cJSON_GetArrayItem(clients, 0);
                if (!client) continue;
                cJSON *password = cJSON_GetObjectItem(client, "password");
                cJSON *method = cJSON_GetObjectItem(client, "method");
                fprintf(out_fp, "- name: \"ss-%d\"\n", i);
                sprintf(proxy_names[proxy_count++], "ss-%d", i);
                fprintf(out_fp, "  type: ss\n");
                fprintf(out_fp, "  server: %s\n", server);
                fprintf(out_fp, "  port: %d\n", p);
                fprintf(out_fp, "  password: %s\n", password ? cJSON_GetStringValue(password) : "");
                fprintf(out_fp, "  cipher: %s\n", method ? cJSON_GetStringValue(method) : "aes-256-gcm");
                fprintf(out_fp, "  udp: true\n");
                print_transport(streamSettings, out_fp, skip_cert);
                if (skip_cert) fprintf(out_fp, "  skip-cert-verify: true\n");
            } else if (strcmp(proto, "socks") == 0) {
                cJSON *clients = cJSON_GetObjectItem(settings, "clients");
                cJSON *client = NULL;
                if (clients && cJSON_IsArray(clients)) {
                    client = cJSON_GetArrayItem(clients, 0);
                }
                cJSON *user = client ? cJSON_GetObjectItem(client, "user") : NULL;
                cJSON *pass = client ? cJSON_GetObjectItem(client, "pass") : NULL;
                fprintf(out_fp, "- name: \"socks5-%d\"\n", i);
                sprintf(proxy_names[proxy_count++], "socks5-%d", i);
                fprintf(out_fp, "  type: socks5\n");
                fprintf(out_fp, "  server: %s\n", server);
                fprintf(out_fp, "  port: %d\n", p);
                if (user) fprintf(out_fp, "  username: %s\n", cJSON_GetStringValue(user));
                if (pass) fprintf(out_fp, "  password: %s\n", cJSON_GetStringValue(pass));
                fprintf(out_fp, "  udp: true\n");
                print_transport(streamSettings, out_fp, skip_cert);
                if (skip_cert) fprintf(out_fp, "  skip-cert-verify: true\n");
            } else if (strcmp(proto, "http") == 0) {
                cJSON *clients = cJSON_GetObjectItem(settings, "clients");
                if (!clients || !cJSON_IsArray(clients)) continue;
                cJSON *client = cJSON_GetArrayItem(clients, 0);
                if (!client) continue;
                cJSON *user = cJSON_GetObjectItem(client, "user");
                cJSON *pass = cJSON_GetObjectItem(client, "pass");
                fprintf(out_fp, "- name: \"http-%d\"\n", i);
                sprintf(proxy_names[proxy_count++], "http-%d", i);
                fprintf(out_fp, "  type: http\n");
                fprintf(out_fp, "  server: %s\n", server);
                fprintf(out_fp, "  port: %d\n", p);
                if (user) fprintf(out_fp, "  username: %s\n", cJSON_GetStringValue(user));
                if (pass) fprintf(out_fp, "  password: %s\n", cJSON_GetStringValue(pass));
                print_transport(streamSettings, out_fp, skip_cert);
                if (skip_cert) fprintf(out_fp, "  skip-cert-verify: true\n");
            } else if (strcmp(proto, "wireguard") == 0) {
                cJSON *privateKey = cJSON_GetObjectItem(settings, "privateKey");
                cJSON *peers = cJSON_GetObjectItem(settings, "peers");
                fprintf(out_fp, "- name: \"wireguard-%d\"\n", i);
                sprintf(proxy_names[proxy_count++], "wireguard-%d", i);
                fprintf(out_fp, "  type: wireguard\n");
                fprintf(out_fp, "  server: %s\n", server);
                fprintf(out_fp, "  port: %d\n", p);
                if (privateKey) fprintf(out_fp, "  private-key: %s\n", cJSON_GetStringValue(privateKey));
                if (peers && cJSON_IsArray(peers)) {
                    cJSON *peer = cJSON_GetArrayItem(peers, 0);
                    if (peer) {
                        cJSON *publicKey = cJSON_GetObjectItem(peer, "publicKey");
                        cJSON *endpoint = cJSON_GetObjectItem(peer, "endpoint");
                        if (publicKey) fprintf(out_fp, "  public-key: %s\n", cJSON_GetStringValue(publicKey));
                        if (endpoint) fprintf(out_fp, "  endpoint: %s\n", cJSON_GetStringValue(endpoint));
                    }
                }
                fprintf(out_fp, "  udp: true\n");
            }
            // Skip unsupported: tunnel
        }
    }

    // Generate proxy groups
    fprintf(out_fp, "proxy-groups:\n");
    fprintf(out_fp, "- name: \"auto\"\n");
    fprintf(out_fp, "  type: url-test\n");
    fprintf(out_fp, "  proxies:\n");
    for (int j = 0; j < proxy_count; j++) {
        fprintf(out_fp, "    - %s\n", proxy_names[j]);
    }
    fprintf(out_fp, "  url: \"http://www.gstatic.com/generate_204\"\n");
    fprintf(out_fp, "  interval: 300\n");

    // Generate routing rules
    fprintf(out_fp, "rules:\n");
    fprintf(out_fp, "- DOMAIN-SUFFIX,google.com,auto\n");
    fprintf(out_fp, "- GEOIP,CN,DIRECT\n");
    fprintf(out_fp, "- MATCH,auto\n");

    cJSON_Delete(root);
    free(buffer);
    fclose(out_fp);
    return 0;
}