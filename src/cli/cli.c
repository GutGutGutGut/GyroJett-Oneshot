#define _POSIX_C_SOURCE 200809L

#include "cli.h"

#include "../client/client.h"
#include "../server/server.h"
#include "../tor/tor.h"
#include "../session/secret.h"
#include "../session/invite.h"
#include "../crypto/crypto.h"

#include <stdio.h>
#include <string.h>

static int read_choice(void)
{
    char buffer[32];

    printf("Escolha: ");
    fflush(stdout);

    if (fgets(buffer, sizeof(buffer), stdin) == NULL)
        return -1;

    int choice;

    if (sscanf(buffer, "%d", &choice) != 1)
        return -1;

    return choice;
}

int gyrojet_cli_run(void)
{
    for (;;) {
        printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
        printf("┃     GyroJett-OneShot2       ┃\n");
        printf("┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫\n");
        printf("┃                             ┃\n");
        printf("┃ O que você deseja fazer?    ┃\n");
        printf("┃                             ┃\n");
        printf("┃  [1] Criar uma sessão       ┃\n");
        printf("┃  [2] Conectar a uma sessão  ┃\n");
        printf("┃  [3] Sair                   ┃\n");
        printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n");

        int choice = read_choice();

        switch (choice) {

            case 1: {
                const unsigned short port = 4242;

                gyrojet_server_t server;
                gyrojet_tor_t tor;

                char secret[
                    GYROJET_SECRET_BUFFER_SIZE
                ];

                char invite[
                    GYROJET_INVITE_MAX_SIZE
                ];

                unsigned char session_key[
                    GYROJET_SESSION_KEY_SIZE
                ];

                memset(
                    secret,
                    0,
                    sizeof(secret)
                );

                memset(
                    invite,
                    0,
                    sizeof(invite)
                );

                memset(
                    session_key,
                    0,
                    sizeof(session_key)
                );

                printf("\n");
                printf("Criar uma sessão\n");
                printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                printf("\n");

                printf("Iniciando servidor...\n");

                if (gyrojet_server_start(
                        &server,
                        port
                    ) < 0) {

                    fprintf(
                        stderr,
                        "GyroJett: não foi possível "
                        "iniciar o servidor.\n"
                    );

                    break;
                }

                printf("Conectando ao Tor...\n");

                if (gyrojet_tor_start(
                        &tor,
                        port
                    ) < 0) {

                    fprintf(
                        stderr,
                        "GyroJett: não foi possível "
                        "criar o Onion Service.\n"
                    );

                    gyrojet_server_stop(
                        &server
                    );

                    break;
                }

                printf(
                    "Gerando segredo da sessão...\n"
                );

                if (gyrojet_secret_generate(
                        secret,
                        sizeof(secret)
                    ) < 0) {

                    fprintf(
                        stderr,
                        "GyroJett: não foi possível "
                        "gerar o segredo.\n"
                    );

                    gyrojet_tor_stop(&tor);
                    gyrojet_server_stop(&server);

                    break;
                }

                printf(
                    "Derivando chave da sessão...\n"
                );

                if (gyrojet_secret_derive_key(
                        secret,
                        session_key
                    ) < 0) {

                    fprintf(
                        stderr,
                        "GyroJett: não foi possível "
                        "derivar a chave da sessão.\n"
                    );

                    gyrojet_crypto_secure_zero(
                        secret,
                        sizeof(secret)
                    );

                    gyrojet_crypto_secure_zero(
                        session_key,
                        sizeof(session_key)
                    );

                    gyrojet_tor_stop(&tor);
                    gyrojet_server_stop(&server);

                    break;
                }

                /*
                 * O convite reúne o endereço Tor
                 * e o segredo da sessão em uma única
                 * string copiável.
                 */
                if (gyrojet_invite_create(
                        tor.onion_address,
                        secret,
                        invite,
                        sizeof(invite)
                    ) < 0) {

                    fprintf(
                        stderr,
                        "GyroJett: não foi possível "
                        "criar o convite.\n"
                    );

                    gyrojet_crypto_secure_zero(
                        secret,
                        sizeof(secret)
                    );

                    gyrojet_crypto_secure_zero(
                        invite,
                        sizeof(invite)
                    );

                    gyrojet_crypto_secure_zero(
                        session_key,
                        sizeof(session_key)
                    );

                    gyrojet_tor_stop(&tor);
                    gyrojet_server_stop(&server);

                    break;
                }

                printf("\n");
                printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
                printf("┃           SESSÃO CRIADA                ┃\n");
                printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n");
                printf("══════════════════════════════════════════\n");

                printf("Convite da sessão:\n");
                printf("%s\n", invite);

                printf("\n");

                printf("\n");
                printf("Aguardando conexão...\n");
                printf(
                    "Pressione Ctrl+C para sair.\n"
                );
                printf("\n");

                /*
                 * O segredo textual e o convite não
                 * precisam permanecer na memória enquanto
                 * a sessão está aguardando conexão.
                 */
                gyrojet_crypto_secure_zero(
                    secret,
                    sizeof(secret)
                );

                gyrojet_crypto_secure_zero(
                    invite,
                    sizeof(invite)
                );

                int result = gyrojet_server_run(
                    &server,
                    session_key
                );

                gyrojet_crypto_secure_zero(
                    session_key,
                    sizeof(session_key)
                );

                gyrojet_tor_stop(&tor);
                gyrojet_server_stop(&server);

                if (result < 0) {
                    fprintf(
                        stderr,
                        "GyroJett: servidor encerrado "
                        "com erro.\n"
                    );
                }

                break;
            }

            case 2: {
                const unsigned short port = 4242;
                char invite[
                    GYROJET_INVITE_MAX_SIZE
                ];

                char onion[
                    GYROJET_TOR_ONION_ADDRESS_SIZE
                ];

                char secret[
                    GYROJET_SECRET_BUFFER_SIZE
                ];

                unsigned char session_key[
                    GYROJET_SESSION_KEY_SIZE
                ];

                memset(
                    invite,
                    0,
                    sizeof(invite)
                );

                memset(
                    onion,
                    0,
                    sizeof(onion)
                );

                memset(
                    secret,
                    0,
                    sizeof(secret)
                );

                memset(
                    session_key,
                    0,
                    sizeof(session_key)
                );

                printf("\n");
                printf("Conectar a uma sessão\n");
                printf("═════════════════════\n");
                printf("\n");

                printf(
                    "Cole o convite da sessão:\n> "
                );

                fflush(stdout);

                if (fgets(
                        invite,
                        sizeof(invite),
                        stdin
                    ) == NULL) {

                    printf(
                        "\nErro ao ler o convite.\n"
                    );

                    gyrojet_crypto_secure_zero(
                        invite,
                        sizeof(invite)
                    );

                    break;
                }

                invite[strcspn(
                    invite,
                    "\n"
                )] = '\0';

                if (invite[0] == '\0') {

                    printf(
                        "Convite inválido.\n"
                    );

                    gyrojet_crypto_secure_zero(
                        invite,
                        sizeof(invite)
                    );

                    break;
                }

                if (gyrojet_invite_parse(
                        invite,
                        onion,
                        sizeof(onion),
                        secret,
                        sizeof(secret)
                    ) < 0) {

                    printf(
                        "Convite inválido ou corrompido.\n"
                    );

                    gyrojet_crypto_secure_zero(
                        invite,
                        sizeof(invite)
                    );

                    gyrojet_crypto_secure_zero(
                        onion,
                        sizeof(onion)
                    );

                    gyrojet_crypto_secure_zero(
                        secret,
                        sizeof(secret)
                    );

                    break;
                }

                printf(
                    "Derivando chave da sessão...\n"
                );

                if (gyrojet_secret_derive_key(
                        secret,
                        session_key
                    ) < 0) {

                    fprintf(
                        stderr,
                        "GyroJett: não foi possível "
                        "derivar a chave da sessão.\n"
                    );

                    gyrojet_crypto_secure_zero(
                        invite,
                        sizeof(invite)
                    );

                    gyrojet_crypto_secure_zero(
                        onion,
                        sizeof(onion)
                    );

                    gyrojet_crypto_secure_zero(
                        secret,
                        sizeof(secret)
                    );

                    gyrojet_crypto_secure_zero(
                        session_key,
                        sizeof(session_key)
                    );

                    break;
                }

                gyrojet_crypto_secure_zero(
                    invite,
                    sizeof(invite)
                );

                gyrojet_crypto_secure_zero(
                    secret,
                    sizeof(secret)
                );

                if (gyrojet_client_connect(
                        onion,
                        port,
                        session_key
                    ) < 0) {

                    printf(
                        "Não foi possível conectar.\n"
                    );
                }

                gyrojet_crypto_secure_zero(
                    onion,
                    sizeof(onion)
                );

                gyrojet_crypto_secure_zero(
                    session_key,
                    sizeof(session_key)
                );

                break;
            }

            case 3:
                printf("\nSaindo...\n");
                return 0;

            default:
                printf("\nOpção inválida.\n");
                break;
        }
    }
}
