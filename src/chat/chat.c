#define _POSIX_C_SOURCE 200809L

#include "chat.h"

#include "../protocol/protocol.h"
#include "../crypto/crypto.h"
#include "../session/auth.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
GYROJET_CHAT_RECV_ERROR = -1,
GYROJET_CHAT_RECV_OK = 0,
GYROJET_CHAT_RECV_CLOSED = 1
};

static int gyrojet_chat_receive_message(
gyrojet_protocol_t *protocol,
unsigned char *message,
size_t message_capacity,
size_t *message_size
)
{
if (protocol == NULL ||
message == NULL ||
message_size == NULL) {
return GYROJET_CHAT_RECV_ERROR;
}


gyrojet_frame_header_t header;

int result = gyrojet_protocol_receive(
    protocol,
    &header,
    message,
    message_capacity,
    message_size
);

if (result > 0)
    return GYROJET_CHAT_RECV_CLOSED;

if (result < 0)
    return GYROJET_CHAT_RECV_ERROR;

if (header.type != GYROJET_FRAME_TEXT)
    return GYROJET_CHAT_RECV_ERROR;

return GYROJET_CHAT_RECV_OK;


}

int gyrojet_chat_run(
gyrojet_connection_t *connection,
const unsigned char key[GYROJET_CHAT_KEY_SIZE],
gyrojet_chat_role_t role
)
{
if (connection == NULL ||
connection->fd < 0 ||
key == NULL ||
(role != GYROJET_CHAT_SERVER &&
role != GYROJET_CHAT_CLIENT)) {
return -1;
}


const char *local_prefix;
const char *remote_prefix;

if (role == GYROJET_CHAT_SERVER) {
    local_prefix = "You> ";
    remote_prefix = "Unknow> ";
} else {
    local_prefix = "You> ";
    remote_prefix = "Unknow> ";
}

gyrojet_protocol_t protocol;

if (gyrojet_protocol_init(
        &protocol,
        connection,
        key
    ) < 0) {
    return -1;
}

if (gyrojet_session_authenticate(
        &protocol,
        role == GYROJET_CHAT_SERVER
            ? GYROJET_AUTH_SERVER
            : GYROJET_AUTH_CLIENT
    ) < 0) {

    fprintf(
        stderr,
        "GyroJett: autenticação da sessão falhou.\n"
    );

    gyrojet_protocol_clear(
        &protocol
    );

    return -1;
}

printf("\n");
printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
printf("┃         GyroJett-OneShot2 Chat         ┃\n");
printf("┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫\n");
printf("┃                                        ┃\n");
printf("┃ Conversa iniciada.                     ┃\n");
printf("┃ Digite uma mensagem e pressione Enter. ┃\n");
printf("┃ Ctrl+D encerra a conversa.             ┃\n");
printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n");

for (;;) {
    fd_set read_fds;

    FD_ZERO(&read_fds);

    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(connection->fd, &read_fds);

    int max_fd = connection->fd;

    if (STDIN_FILENO > max_fd)
        max_fd = STDIN_FILENO;

    int result = select(
        max_fd + 1,
        &read_fds,
        NULL,
        NULL,
        NULL
    );

    if (result < 0) {
        if (errno == EINTR)
            continue;

        perror("GyroJett: select");

        gyrojet_protocol_clear(&protocol);

        return -1;
    }

    /*
     * Primeiro verificamos o socket.
     */
    if (FD_ISSET(
            connection->fd,
            &read_fds
        )) {

        unsigned char message[
            GYROJET_CHAT_MAX_MESSAGE_SIZE + 1
        ];

        size_t message_size = 0;

        result = gyrojet_chat_receive_message(
            &protocol,
            message,
            GYROJET_CHAT_MAX_MESSAGE_SIZE,
            &message_size
        );

        if (result == GYROJET_CHAT_RECV_CLOSED) {
            printf(
                "\n%s encerrou a conversa.\n",
                remote_prefix
            );

            gyrojet_crypto_secure_zero(
                message,
                sizeof(message)
            );

            gyrojet_protocol_clear(&protocol);

            return 0;
        }

        if (result != GYROJET_CHAT_RECV_OK) {
            fprintf(
                stderr,
                "\nGyroJett: mensagem inválida "
                "ou conexão interrompida.\n"
            );

            gyrojet_crypto_secure_zero(
                message,
                sizeof(message)
            );

            gyrojet_protocol_clear(&protocol);

            return -1;
        }

        message[message_size] = '\0';

        printf(
            "%s%s\n",
            remote_prefix,
            message
        );

        fflush(stdout);

        gyrojet_crypto_secure_zero(
            message,
            sizeof(message)
        );
    }

    /*
     * Agora verificamos o terminal.
     */
    if (FD_ISSET(
            STDIN_FILENO,
            &read_fds
        )) {

        unsigned char message[
            GYROJET_CHAT_MAX_MESSAGE_SIZE
        ];

        memset(
            message,
            0,
            sizeof(message)
        );

        if (fgets(
                (char *)message,
                sizeof(message),
                stdin
            ) == NULL) {

            printf(
                "\nEncerrando a conversa...\n"
            );

            shutdown(
                connection->fd,
                SHUT_WR
            );

            gyrojet_crypto_secure_zero(
                message,
                sizeof(message)
            );

            gyrojet_protocol_clear(&protocol);

            return 0;
        }

        size_t message_size = strlen(
            (char *)message
        );

        if (message_size > 0 &&
            message[message_size - 1] == '\n') {

            message[message_size - 1] = '\0';
            message_size--;
        }

        if (message_size == 0) {
            gyrojet_crypto_secure_zero(
                message,
                sizeof(message)
            );

            continue;
        }

        if (gyrojet_protocol_send(
                &protocol,
                GYROJET_FRAME_TEXT,
                message,
                message_size
            ) < 0) {

            fprintf(
                stderr,
                "GyroJett: falha ao enviar mensagem.\n"
            );

            gyrojet_crypto_secure_zero(
                message,
                sizeof(message)
            );

            gyrojet_protocol_clear(&protocol);

            return -1;
        }

        printf(
            "%s%s\n",
            local_prefix,
            message
        );

        fflush(stdout);

        gyrojet_crypto_secure_zero(
            message,
            sizeof(message)
        );
    }
}

}

