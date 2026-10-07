#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        return 1;
    }

    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        printf("Invalid address/ Address not supported\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("connect: Connection refused\n");
        return -1;
    }

    printf("Connected to RemoteOps Agent.\n");

    char command[256];
    char buffer[1024];

    while (1) {
        memset(command, 0, sizeof(command));
        if (fgets(command, sizeof(command), stdin) == NULL) break;

        command[strcspn(command, "\r\n")] = 0;
        if (strlen(command) == 0) continue;

        char send_buf[280];
        snprintf(send_buf, sizeof(send_buf), "%s\n", command);
        send(sock, send_buf, strlen(send_buf), 0);

        memset(buffer, 0, sizeof(buffer));
        int valread = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (valread > 0) {
            printf("Agent response: %s", buffer);
        } else {
            printf("Connection closed by agent.\n");
            break;
        }

        if (strcmp(command, "QUIT") == 0) break;
    }

    close(sock);
    return 0;
}
