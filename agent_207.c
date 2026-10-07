#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 9410
#define BACKLOG 5
#define AUTH_TOKEN "OPS-2207"
#define SID "SID:7022"

/* Helper function to check if EXEC command is whitelisted */
int is_whitelisted(const char *cmd)
{
    return (strcmp(cmd, "DATE") == 0 ||
            strcmp(cmd, "UPTIME") == 0 ||
            strcmp(cmd, "DISKFREE") == 0 ||
            strcmp(cmd, "HOSTNAME") == 0 ||
            strcmp(cmd, "WHOAMI") == 0);
}

/* Helper function to get command output using popen */
void get_cmd_output(const char *sys_cmd, char *out_buf, size_t max_len)
{
    FILE *fp = popen(sys_cmd, "r");
    if (!fp)
    {
        snprintf(out_buf, max_len, "ERR 003 EXEC_FAILED " SID "\n");
        return;
    }

    char temp[512] = {0};
    if (fgets(temp, sizeof(temp), fp) != NULL)
    {
        temp[strcspn(temp, "\r\n")] = '\0';
        snprintf(out_buf, max_len, "OK EXEC_RESULT %s " SID "\n", temp);
    }
    else
    {
        snprintf(out_buf, max_len, "OK EXEC_RESULT NONE " SID "\n");
    }
    pclose(fp);
}

int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, BACKLOG) < 0)
    {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("RemoteOps Agent listening on TCP port %d...\n", PORT);

    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0)
    {
        perror("accept");
        close(server_fd);
        return 1;
    }

    printf("Controller connected.\n");

    char buffer[256];
    ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0)
    {
        close(client_fd);
        close(server_fd);
        return 1;
    }

    buffer[bytes_received] = '\0';
    buffer[strcspn(buffer, "\r\n")] = '\0';
    printf("Received: %s\n", buffer);

    /* 1. AUTH Check */
    if (strcmp(buffer, "AUTH " AUTH_TOKEN) == 0)
    {
        const char *auth_ok = "OK AUTH " SID "\n";
        send(client_fd, auth_ok, strlen(auth_ok), 0);
        printf("Authentication successful.\n");

        /* Command loop for authenticated session */
        while ((bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0)) > 0)
        {
            buffer[bytes_received] = '\0';
            buffer[strcspn(buffer, "\r\n")] = '\0';
            printf("Received: %s\n", buffer);

            if (strcmp(buffer, "SYSINFO") == 0)
            {
                const char *resp = "OK SYSINFO CPU:0.15 MEM:256MB UPTIME:3600 " SID "\n";
                send(client_fd, resp, strlen(resp), 0);
            }
            else if (strcmp(buffer, "LISTPROC") == 0)
            {
                FILE *fp = popen("ps -e -o comm= | head -n 5 | tr '\n' ','", "r");
                char procs[256] = {0};
                if (fp && fgets(procs, sizeof(procs), fp))
                {
                    procs[strcspn(procs, "\r\n")] = '\0';
                    char resp[512];
                    snprintf(resp, sizeof(resp), "OK PROCS %s " SID "\n", procs);
                    send(client_fd, resp, strlen(resp), 0);
                }
                if (fp) pclose(fp);
            }
            else if (strncmp(buffer, "EXEC ", 5) == 0)
            {
                char *cmd_name = buffer + 5;
                if (is_whitelisted(cmd_name))
                {
                    char resp[512];
                    if (strcmp(cmd_name, "DATE") == 0)
                        get_cmd_output("date", resp, sizeof(resp));
                    else if (strcmp(cmd_name, "UPTIME") == 0)
                        get_cmd_output("uptime -p", resp, sizeof(resp));
                    else if (strcmp(cmd_name, "DISKFREE") == 0)
                        get_cmd_output("df -h / | tail -n 1 | awk '{print $4}'", resp, sizeof(resp));
                    else if (strcmp(cmd_name, "HOSTNAME") == 0)
                        get_cmd_output("hostname", resp, sizeof(resp));
                    else if (strcmp(cmd_name, "WHOAMI") == 0)
                        get_cmd_output("whoami", resp, sizeof(resp));

                    send(client_fd, resp, strlen(resp), 0);
                }
                else
                {
                    const char *err_resp = "ERR 002 COMMAND NOT ALLOWED " SID "\n";
                    send(client_fd, err_resp, strlen(err_resp), 0);
                }
            }
            else if (strcmp(buffer, "QUIT") == 0)
            {
                const char *bye_resp = "OK BYE " SID "\n";
                send(client_fd, bye_resp, strlen(bye_resp), 0);
                break;
            }
            else
            {
                const char *err_resp = "ERR 001 UNKNOWN_COMMAND " SID "\n";
                send(client_fd, err_resp, strlen(err_resp), 0);
            }
        }
    }
    else
    {
        const char *auth_fail = "ERR 001 AUTH_FAILED " SID "\n";
        send(client_fd, auth_fail, strlen(auth_fail), 0);
        printf("Authentication failed.\n");
    }

    close(client_fd);
    close(server_fd);
    return 0;
}
