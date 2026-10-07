#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 9410
#define SERVER_IP "192.168.179.128"

void send_cmd(int sock_fd, const char *cmd)
{
    char buffer[1024];
    send(sock_fd, cmd, strlen(cmd), 0);
    printf("Sent: %s", cmd);

    ssize_t bytes = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0)
    {
        buffer[bytes] = '\0';
        printf("Agent response: %s", buffer);
    }
}

int main(void)
{
    int sock_fd;
    struct sockaddr_in server_addr;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        close(sock_fd);
        return 1;
    }

    printf("Connected to RemoteOps Agent.\n");

    /* 1. AUTH */
    send_cmd(sock_fd, "AUTH OPS-2207\n");

    /* 2. SYSINFO */
    send_cmd(sock_fd, "SYSINFO\n");

    /* 3. LISTPROC */
    send_cmd(sock_fd, "LISTPROC\n");

    /* 4. Whitelisted EXEC (Allowed) */
    send_cmd(sock_fd, "EXEC DATE\n");

    /* 5. Whitelisted EXEC (Disallowed - Testing Error Case) */
    send_cmd(sock_fd, "EXEC RM\n");

    /* 6. QUIT */
    send_cmd(sock_fd, "QUIT\n");

    close(sock_fd);
    return 0;
}
