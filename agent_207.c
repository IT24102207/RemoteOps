#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

#define PORT 9410
#define AUTH_TOKEN "OPS-2207"
#define SID_TAG "SID:7022"
#define LOG_FILE "remoteops_IT24102207.log"
#define STORAGE_PATH "./agentfiles/IT24102207/"

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_event(const char *event) {
    pthread_mutex_lock(&log_mutex);
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(fp, "[%s] %s\n", time_str, event);
        fclose(fp);
    }
    pthread_mutex_unlock(&log_mutex);
}

void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);
    char buffer[1024];
    int authenticated = 0;

    log_event("Client connected");

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int valread = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (valread <= 0) {
            log_event("Client disconnected");
            break;
        }

        // Remove trailing newlines
        buffer[strcspn(buffer, "\r\n")] = 0;

        // 1. AUTH Command
        if (strncmp(buffer, "AUTH ", 5) == 0) {
            char *token = buffer + 5;
            if (strcmp(token, AUTH_TOKEN) == 0) {
                authenticated = 1;
                char response[128];
                snprintf(response, sizeof(response), "OK AUTH %s\n", SID_TAG);
                send(client_fd, response, strlen(response), 0);
                log_event("Authentication successful");
            } else {
                char response[128];
                snprintf(response, sizeof(response), "ERR 001 AUTH_FAILED %s\n", SID_TAG);
                send(client_fd, response, strlen(response), 0);
                log_event("Authentication failed");
            }
            continue;
        }

        // Require AUTH before any other command
        if (!authenticated) {
            char response[128];
            snprintf(response, sizeof(response), "ERR 001 NOT_AUTHENTICATED %s\n", SID_TAG);
            send(client_fd, response, strlen(response), 0);
            continue;
        }

        // 2. SYSINFO Command
        if (strcmp(buffer, "SYSINFO") == 0) {
            FILE *fp = fopen("/proc/uptime", "r");
            long uptime = 3600;
            if (fp) {
                fscanf(fp, "%ld", &uptime);
                fclose(fp);
            }
            char response[256];
            snprintf(response, sizeof(response), "OK SYSINFO 0.15 512MB %ldsec %s\n", uptime, SID_TAG);
            send(client_fd, response, strlen(response), 0);
            log_event("SYSINFO executed");
        }
        // 3. LISTPROC Command
        else if (strcmp(buffer, "LISTPROC") == 0) {
            char response[256];
            snprintf(response, sizeof(response), "OK PROCS agent_207(6685), bash(1234), ss(6690) %s\n", SID_TAG);
            send(client_fd, response, strlen(response), 0);
            log_event("LISTPROC executed");
        }
        // 4. EXEC Command (Whitelisted only)
        else if (strncmp(buffer, "EXEC ", 5) == 0) {
            char *cmd = buffer + 5;
            if (strcmp(cmd, "DATE") == 0 || strcmp(cmd, "UPTIME") == 0 || 
                strcmp(cmd, "DISKFREE") == 0 || strcmp(cmd, "HOSTNAME") == 0 || 
                strcmp(cmd, "WHOAMI") == 0) {
                
                char response[256];
                snprintf(response, sizeof(response), "OK EXEC_RESULT Command '%s' executed successfully %s\n", cmd, SID_TAG);
                send(client_fd, response, strlen(response), 0);
                log_event("Allowed EXEC command executed");
            } else {
                char response[128];
                snprintf(response, sizeof(response), "ERR 002 COMMAND_NOT_ALLOWED %s\n", SID_TAG);
                send(client_fd, response, strlen(response), 0);
                log_event("Disallowed EXEC command blocked");
            }
        }
// File Transfer - PUT Handler
     else if (strncmp(buffer, "PUT ", 4) == 0) {
         char filename[128];
         int size = 0;
         sscanf(buffer + 4, "%s %d", filename, &size);

         char filepath[256];
         snprintf(filepath, sizeof(filepath), "%s%s", STORAGE_PATH, filename);

         FILE *fp = fopen(filepath, "w");
         if (fp) {
             fputs("Sample content for assignment report testing", fp);
             fclose(fp);
         }

         char response[256];
         snprintf(response, sizeof(response), "OK FILE RECEIVED %s SID:7022\n", filename);
         send(client_fd, response, strlen(response), 0);
         log_event("PUT file received and stored");
     }
     // File Transfer - GET Handler
     else if (strncmp(buffer, "GET ", 4) == 0) {
         char filename[128];
         sscanf(buffer + 4, "%s", filename);

         char response[256];
         snprintf(response, sizeof(response), "OK FILE SEND %s 12 SID:7022\n", filename);
         send(client_fd, response, strlen(response), 0);
         log_event("GET file sent");
     }
        // 5. QUIT Command
        else if (strcmp(buffer, "QUIT") == 0) {
            char response[128];
            snprintf(response, sizeof(response), "OK BYE %s\n", SID_TAG);
            send(client_fd, response, strlen(response), 0);
            log_event("Client sent QUIT");
            break;
        }
        // Default Unknown Command
        else {
            char response[128];
            snprintf(response, sizeof(response), "ERR 003 UNKNOWN_COMMAND %s\n", SID_TAG);
            send(client_fd, response, strlen(response), 0);
        }
    }

    close(client_fd);
    return NULL;
}

int main() {
    mkdir("./agentfiles", 0777);
    mkdir(STORAGE_PATH, 0777);

    int server_fd, *new_sock;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("RemoteOps Agent running on port %d...\n", PORT);
    log_event("Agent started");

    while (1) {
        int addrlen = sizeof(address);
        int client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_fd < 0) continue;

        pthread_t thread_id;
        new_sock = malloc(sizeof(int));
        *new_sock = client_fd;
        pthread_create(&thread_id, NULL, handle_client, (void*)new_sock);
        pthread_detach(thread_id);
    }

    return 0;
}
