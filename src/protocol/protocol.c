#define _POSIX_C_SOURCE 200809L

#include "protocol.h"

#include "../crypto/aead.h"
#include "../crypto/crypto.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef GYROJET_DEBUG

#define PROTO_DEBUG(...) \
    do { \
        fprintf(stderr, "[PROTO DEBUG] "); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } while (0)

#else

#define PROTO_DEBUG(...) \
    do { \
    } while (0)

#endif

static void gyrojet_protocol_debug_hex(
    const char *label,
    const unsigned char *buffer,
    size_t size
)
{
    if (label == NULL) {
        return;
    }

    fprintf(
        stderr,
        "[PROTO DEBUG] %s (%zu bytes): ",
        label,
        size
    );

    if (buffer == NULL && size != 0) {
        fprintf(stderr, "<NULL>\n");
        return;
    }

    /*
     * Não despejamos chaves, plaintext ou ciphertext completos.
     * Mostramos somente os primeiros bytes para diagnóstico.
     */
    size_t shown = size < 16 ? size : 16;

    for (size_t i = 0; i < shown; ++i) {
        fprintf(stderr, "%02x", buffer[i]);
    }

    if (size > shown) {
        fprintf(stderr, "...");
    }

    fprintf(stderr, "\n");
}

static int gyrojet_protocol_send_all(
    gyrojet_connection_t *connection,
    const void *buffer,
    size_t size
)
{
    if (connection == NULL ||
        buffer == NULL ||
        connection->fd < 0) {

        PROTO_DEBUG(
            "send_all: argumentos inválidos "
            "(connection=%p buffer=%p fd=%d)",
            (void *)connection,
            buffer,
            connection != NULL ? connection->fd : -999
        );

        return -1;
    }

    PROTO_DEBUG(
        "send_all: iniciando envio de %zu bytes pelo fd=%d",
        size,
        connection->fd
    );

    if (gyrojet_connection_send(
            connection,
            buffer,
            size
        ) < 0) {

        PROTO_DEBUG(
            "send_all: connection_send falhou "
            "errno=%d (%s)",
            errno,
            strerror(errno)
        );

        return -1;
    }

    PROTO_DEBUG(
        "send_all: envio concluído (%zu bytes)",
        size
    );

    return 0;
}

static int gyrojet_protocol_recv_all(
    gyrojet_connection_t *connection,
    void *buffer,
    size_t size
)
{
    if (connection == NULL ||
        buffer == NULL ||
        connection->fd < 0) {

        PROTO_DEBUG(
            "recv_all: argumentos inválidos "
            "(connection=%p buffer=%p fd=%d)",
            (void *)connection,
            buffer,
            connection != NULL ? connection->fd : -999
        );

        return -1;
    }

    unsigned char *ptr = buffer;
    size_t received = 0;

    PROTO_DEBUG(
        "recv_all: aguardando %zu bytes pelo fd=%d",
        size,
        connection->fd
    );

    while (received < size) {
        ssize_t result = gyrojet_connection_recv(
            connection,
            ptr + received,
            size - received
        );

        if (result < 0) {
            PROTO_DEBUG(
                "recv_all: connection_recv retornou %zd "
                "errno=%d (%s)",
                result,
                errno,
                strerror(errno)
            );

            return -1;
        }

        if (result == 0) {
            PROTO_DEBUG(
                "recv_all: conexão encerrada pelo peer"
            );

            return 1;
        }

        received += (size_t)result;

        PROTO_DEBUG(
            "recv_all: recebido=%zu/%zu",
            received,
            size
        );
    }

    PROTO_DEBUG("recv_all: recepção concluída");

    return 0;
}

static int gyrojet_protocol_build_aad(
    const unsigned char header[
        GYROJET_PROTOCOL_HEADER_SIZE
    ],
    const unsigned char nonce[
        GYROJET_PROTOCOL_NONCE_SIZE
    ],
    unsigned char aad[
        GYROJET_PROTOCOL_HEADER_SIZE +
        GYROJET_PROTOCOL_NONCE_SIZE
    ]
)
{
    if (header == NULL ||
        nonce == NULL ||
        aad == NULL) {

        PROTO_DEBUG(
            "build_aad: argumento NULL"
        );

        return -1;
    }

    memcpy(
        aad,
        header,
        GYROJET_PROTOCOL_HEADER_SIZE
    );

    memcpy(
        aad + GYROJET_PROTOCOL_HEADER_SIZE,
        nonce,
        GYROJET_PROTOCOL_NONCE_SIZE
    );

    PROTO_DEBUG(
        "build_aad: AAD construída (%zu bytes)",
        sizeof(
            unsigned char[
                GYROJET_PROTOCOL_HEADER_SIZE +
                GYROJET_PROTOCOL_NONCE_SIZE
            ]
        )
    );

    return 0;
}

int gyrojet_protocol_init(
    gyrojet_protocol_t *protocol,
    gyrojet_connection_t *connection,
    const unsigned char key[GYROJET_PROTOCOL_KEY_SIZE]
)
{
    PROTO_DEBUG("protocol_init: iniciando");

    if (protocol == NULL ||
        connection == NULL ||
        key == NULL ||
        connection->fd < 0) {

        PROTO_DEBUG(
            "protocol_init: argumentos inválidos "
            "(protocol=%p connection=%p key=%p fd=%d)",
            (void *)protocol,
            (void *)connection,
            (const void *)key,
            connection != NULL ? connection->fd : -999
        );

        return -1;
    }

    memset(
        protocol,
        0,
        sizeof(*protocol)
    );

    protocol->connection = connection;

    memcpy(
        protocol->key,
        key,
        sizeof(protocol->key)
    );

    protocol->send_sequence = 0;
    protocol->receive_sequence = 0;

    PROTO_DEBUG(
        "protocol_init: OK fd=%d send_seq=%llu recv_seq=%llu",
        connection->fd,
        (unsigned long long)protocol->send_sequence,
        (unsigned long long)protocol->receive_sequence
    );

    return 0;
}

int gyrojet_protocol_send(
    gyrojet_protocol_t *protocol,
    uint8_t type,
    const unsigned char *payload,
    size_t payload_size
)
{
    PROTO_DEBUG(
        "protocol_send: início type=%u payload_size=%zu",
        (unsigned)type,
        payload_size
    );

    if (protocol == NULL ||
        protocol->connection == NULL) {

        PROTO_DEBUG(
            "protocol_send: protocol ou connection NULL"
        );

        return -1;
    }

    PROTO_DEBUG(
        "protocol_send: fd=%d send_sequence=%llu",
        protocol->connection->fd,
        (unsigned long long)protocol->send_sequence
    );

    if (payload == NULL && payload_size != 0) {
        PROTO_DEBUG(
            "protocol_send: payload NULL com tamanho != 0"
        );

        return -1;
    }

    if (payload_size >
        GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE) {

        PROTO_DEBUG(
            "protocol_send: payload excede máximo "
            "(%zu > %u)",
            payload_size,
            GYROJET_PROTOCOL_MAX_PAYLOAD_SIZE
        );

        return -1;
    }

    if (payload_size > UINT32_MAX) {
        PROTO_DEBUG(
            "protocol_send: payload excede UINT32_MAX"
        );

        return -1;
    }

    gyrojet_frame_header_t frame_header = {
        .version = GYROJET_PROTOCOL_VERSION,
        .type = type,
        .flags = 0,
        .sequence = protocol->send_sequence,
        .payload_size = (uint32_t)payload_size
    };

    unsigned char header[
        GYROJET_PROTOCOL_HEADER_SIZE
    ];

    unsigned char nonce[
        GYROJET_PROTOCOL_NONCE_SIZE
    ];

    unsigned char tag[
        GYROJET_PROTOCOL_TAG_SIZE
    ];

    unsigned char aad[
        GYROJET_PROTOCOL_HEADER_SIZE +
        GYROJET_PROTOCOL_NONCE_SIZE
    ];

    unsigned char *ciphertext = NULL;

    int result = -1;

    PROTO_DEBUG(
        "protocol_send: header preparado "
        "version=%u type=%u flags=%u sequence=%llu payload=%u",
        (unsigned)frame_header.version,
        (unsigned)frame_header.type,
        (unsigned)frame_header.flags,
        (unsigned long long)frame_header.sequence,
        (unsigned)frame_header.payload_size
    );

    /*
     * HEADER
     */
    if (gyrojet_frame_header_encode(
            &frame_header,
            header
        ) < 0) {

        PROTO_DEBUG(
            "protocol_send: FALHA em frame_header_encode"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_send: header_encode OK"
    );

    gyrojet_protocol_debug_hex(
        "HEADER",
        header,
        sizeof(header)
    );

    /*
     * NONCE
     */
    if (gyrojet_crypto_random(
            nonce,
            sizeof(nonce)
        ) < 0) {

        PROTO_DEBUG(
            "protocol_send: FALHA em crypto_random"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_send: nonce gerado"
    );

    gyrojet_protocol_debug_hex(
        "NONCE",
        nonce,
        sizeof(nonce)
    );

    /*
     * AAD
     */
    if (gyrojet_protocol_build_aad(
            header,
            nonce,
            aad
        ) < 0) {

        PROTO_DEBUG(
            "protocol_send: FALHA em build_aad"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_send: AAD OK"
    );

    /*
     * CIPHERTEXT
     */
    if (payload_size > 0) {
        PROTO_DEBUG(
            "protocol_send: alocando ciphertext de %zu bytes",
            payload_size
        );

        ciphertext = malloc(payload_size);

        if (ciphertext == NULL) {
            PROTO_DEBUG(
                "protocol_send: malloc(%zu) falhou",
                payload_size
            );

            goto cleanup;
        }

        PROTO_DEBUG(
            "protocol_send: ciphertext alocado"
        );
    }

    /*
     * AES-GCM
     */
    PROTO_DEBUG(
        "protocol_send: chamando gyrojet_aead_encrypt()"
    );

    if (gyrojet_aead_encrypt(
            protocol->key,
            nonce,
            payload,
            payload_size,
            aad,
            sizeof(aad),
            ciphertext,
            tag
        ) < 0) {

        PROTO_DEBUG(
            "protocol_send: FALHA em gyrojet_aead_encrypt()"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_send: aead_encrypt OK"
    );

    gyrojet_protocol_debug_hex(
        "TAG",
        tag,
        sizeof(tag)
    );

    if (payload_size > 0) {
        gyrojet_protocol_debug_hex(
            "CIPHERTEXT",
            ciphertext,
            payload_size
        );
    }

    /*
     * ENVIO DO HEADER
     */
    PROTO_DEBUG(
        "protocol_send: enviando HEADER"
    );

    if (gyrojet_protocol_send_all(
            protocol->connection,
            header,
            sizeof(header)
        ) < 0) {

        PROTO_DEBUG(
            "protocol_send: FALHA enviando HEADER"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_send: HEADER enviado"
    );

    /*
     * ENVIO DO NONCE
     */
    PROTO_DEBUG(
        "protocol_send: enviando NONCE"
    );

    if (gyrojet_protocol_send_all(
            protocol->connection,
            nonce,
            sizeof(nonce)
        ) < 0) {

        PROTO_DEBUG(
            "protocol_send: FALHA enviando NONCE"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_send: NONCE enviado"
    );

    /*
     * ENVIO DO CIPHERTEXT
     */
    if (payload_size > 0) {
        PROTO_DEBUG(
            "protocol_send: enviando CIPHERTEXT (%zu bytes)",
            payload_size
        );

        if (gyrojet_protocol_send_all(
                protocol->connection,
                ciphertext,
                payload_size
            ) < 0) {

            PROTO_DEBUG(
                "protocol_send: FALHA enviando CIPHERTEXT"
            );

            goto cleanup;
        }

        PROTO_DEBUG(
            "protocol_send: CIPHERTEXT enviado"
        );
    }

    /*
     * ENVIO DA TAG
     */
    PROTO_DEBUG(
        "protocol_send: enviando TAG"
    );

    if (gyrojet_protocol_send_all(
            protocol->connection,
            tag,
            sizeof(tag)
        ) < 0) {

        PROTO_DEBUG(
            "protocol_send: FALHA enviando TAG"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_send: TAG enviada"
    );

    /*
     * Só incrementamos a sequência depois de o frame inteiro
     * ter sido transmitido.
     */
    protocol->send_sequence++;

    PROTO_DEBUG(
        "protocol_send: SUCESSO sequence agora=%llu",
        (unsigned long long)protocol->send_sequence
    );

    result = 0;

cleanup:

    if (ciphertext != NULL) {
        PROTO_DEBUG(
            "protocol_send: limpando ciphertext"
        );

        gyrojet_crypto_secure_zero(
            ciphertext,
            payload_size
        );

        free(ciphertext);
    }

    gyrojet_crypto_secure_zero(
        nonce,
        sizeof(nonce)
    );

    gyrojet_crypto_secure_zero(
        tag,
        sizeof(tag)
    );

    gyrojet_crypto_secure_zero(
        aad,
        sizeof(aad)
    );

    PROTO_DEBUG(
        "protocol_send: finalizando result=%d",
        result
    );

    return result;
}

int gyrojet_protocol_receive(
    gyrojet_protocol_t *protocol,
    gyrojet_frame_header_t *header,
    unsigned char *payload,
    size_t payload_capacity,
    size_t *payload_size
)
{
    PROTO_DEBUG(
        "protocol_receive: início"
    );

    if (protocol == NULL ||
        protocol->connection == NULL ||
        header == NULL ||
        payload_size == NULL) {

        PROTO_DEBUG(
            "protocol_receive: argumentos inválidos"
        );

        return -1;
    }

    *payload_size = 0;

    unsigned char raw_header[
        GYROJET_PROTOCOL_HEADER_SIZE
    ];

    unsigned char nonce[
        GYROJET_PROTOCOL_NONCE_SIZE
    ];

    unsigned char tag[
        GYROJET_PROTOCOL_TAG_SIZE
    ];

    unsigned char aad[
        GYROJET_PROTOCOL_HEADER_SIZE +
        GYROJET_PROTOCOL_NONCE_SIZE
    ];

    unsigned char *ciphertext = NULL;

    int result = -1;

    PROTO_DEBUG(
        "protocol_receive: fd=%d esperando HEADER",
        protocol->connection->fd
    );

    int recv_result = gyrojet_protocol_recv_all(
        protocol->connection,
        raw_header,
        sizeof(raw_header)
    );

    if (recv_result != 0) {
        PROTO_DEBUG(
            "protocol_receive: falha/fechamento recebendo HEADER "
            "(result=%d)",
            recv_result
        );

        return recv_result;
    }

    PROTO_DEBUG(
        "protocol_receive: HEADER recebido"
    );

    gyrojet_protocol_debug_hex(
        "RAW HEADER",
        raw_header,
        sizeof(raw_header)
    );

    if (gyrojet_frame_header_decode(
            raw_header,
            header
        ) < 0) {

        PROTO_DEBUG(
            "protocol_receive: FALHA em frame_header_decode"
        );

        return -1;
    }

    PROTO_DEBUG(
        "protocol_receive: header OK "
        "version=%u type=%u flags=%u sequence=%llu payload=%u",
        (unsigned)header->version,
        (unsigned)header->type,
        (unsigned)header->flags,
        (unsigned long long)header->sequence,
        (unsigned)header->payload_size
    );

    if (header->sequence !=
        protocol->receive_sequence) {

        PROTO_DEBUG(
            "protocol_receive: sequência inválida "
            "recebida=%llu esperada=%llu",
            (unsigned long long)header->sequence,
            (unsigned long long)protocol->receive_sequence
        );

        return -1;
    }

    if ((size_t)header->payload_size >
        payload_capacity) {

        PROTO_DEBUG(
            "protocol_receive: payload grande demais "
            "(%u > %zu)",
            (unsigned)header->payload_size,
            payload_capacity
        );

        return -1;
    }

    if (header->payload_size > 0 &&
        payload == NULL) {

        PROTO_DEBUG(
            "protocol_receive: payload NULL com tamanho > 0"
        );

        return -1;
    }

    PROTO_DEBUG(
        "protocol_receive: esperando NONCE"
    );

    recv_result = gyrojet_protocol_recv_all(
        protocol->connection,
        nonce,
        sizeof(nonce)
    );

    if (recv_result != 0) {
        PROTO_DEBUG(
            "protocol_receive: falha recebendo NONCE"
        );

        return recv_result;
    }

    PROTO_DEBUG(
        "protocol_receive: NONCE recebido"
    );

    gyrojet_protocol_debug_hex(
        "NONCE",
        nonce,
        sizeof(nonce)
    );

    if (header->payload_size > 0) {
        PROTO_DEBUG(
            "protocol_receive: alocando ciphertext de %u bytes",
            (unsigned)header->payload_size
        );

        ciphertext = malloc(
            header->payload_size
        );

        if (ciphertext == NULL) {
            PROTO_DEBUG(
                "protocol_receive: malloc ciphertext falhou"
            );

            goto cleanup;
        }

        recv_result = gyrojet_protocol_recv_all(
            protocol->connection,
            ciphertext,
            header->payload_size
        );

        if (recv_result != 0) {
            PROTO_DEBUG(
                "protocol_receive: falha recebendo CIPHERTEXT"
            );

            goto cleanup;
        }

        PROTO_DEBUG(
            "protocol_receive: CIPHERTEXT recebido"
        );

        gyrojet_protocol_debug_hex(
            "CIPHERTEXT",
            ciphertext,
            header->payload_size
        );
    }

    PROTO_DEBUG(
        "protocol_receive: esperando TAG"
    );

    recv_result = gyrojet_protocol_recv_all(
        protocol->connection,
        tag,
        sizeof(tag)
    );

    if (recv_result != 0) {
        PROTO_DEBUG(
            "protocol_receive: falha recebendo TAG"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_receive: TAG recebida"
    );

    gyrojet_protocol_debug_hex(
        "TAG",
        tag,
        sizeof(tag)
    );

    if (gyrojet_protocol_build_aad(
            raw_header,
            nonce,
            aad
        ) < 0) {

        PROTO_DEBUG(
            "protocol_receive: FALHA em build_aad"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_receive: AAD OK"
    );

    PROTO_DEBUG(
        "protocol_receive: chamando gyrojet_aead_decrypt()"
    );

    if (gyrojet_aead_decrypt(
            protocol->key,
            nonce,
            ciphertext,
            header->payload_size,
            aad,
            sizeof(aad),
            tag,
            payload
        ) < 0) {

        PROTO_DEBUG(
            "protocol_receive: FALHA em gyrojet_aead_decrypt()"
        );

        goto cleanup;
    }

    PROTO_DEBUG(
        "protocol_receive: aead_decrypt OK"
    );

    *payload_size = header->payload_size;

    protocol->receive_sequence++;

    PROTO_DEBUG(
        "protocol_receive: SUCESSO receive_sequence agora=%llu",
        (unsigned long long)protocol->receive_sequence
    );

    result = 0;

cleanup:

    if (ciphertext != NULL) {
        gyrojet_crypto_secure_zero(
            ciphertext,
            header->payload_size
        );

        free(ciphertext);
    }

    gyrojet_crypto_secure_zero(
        nonce,
        sizeof(nonce)
    );

    gyrojet_crypto_secure_zero(
        tag,
        sizeof(tag)
    );

    gyrojet_crypto_secure_zero(
        aad,
        sizeof(aad)
    );

    PROTO_DEBUG(
        "protocol_receive: finalizando result=%d",
        result
    );

    return result;
}

void gyrojet_protocol_clear(
    gyrojet_protocol_t *protocol
)
{
    if (protocol == NULL)
        return;

    PROTO_DEBUG(
        "protocol_clear: limpando estado do protocolo"
    );

    gyrojet_crypto_secure_zero(
        protocol,
        sizeof(*protocol)
    );
}
